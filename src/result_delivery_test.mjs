// R46 regression test: an internal result must be RETRIEVABLE by its payer.
//
// BUG: /v1/compress/result returned only `bucket` + `key` with a note telling the
// caller to "fetch it with your own S3 credentials". That is right for a BYO
// bucket, but BYO storage is only REQUIRED at >=10 GB -- so a normal small-file
// customer paid, received coordinates for the PROVIDER's bucket, and had no way
// to read the file. The service was unusable in its default mode.
//
// Fix: the Worker holds an R2 binding and streams the object itself, AFTER a
// durable receipt exists and the EIP-712 payer has been recovered and matched to
// it. (R2's Worker binding has no presigning API, and presigning would require
// giving the Worker S3 credentials it must never hold.)
//
// Asserts: a proven payer receives the BYTES; an unmatched payment gets nothing;
// the key comes from the receipt, not from caller input; and with no binding
// the response stays scoped to the caller's own bucket.
import { readFileSync } from 'node:fs';
import gw from './index.js';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf8'));
const decoded = JSON.parse(Buffer.from(vec.header_b64url, 'base64url').toString());
const AUTHZ = decoded.payload.authorization;
const NONCE = String(AUTHZ.nonce).replace(/^0x/, '').toLowerCase();

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const kv = new Map();
const gets = [];

// A faithful stand-in for the R2 Worker binding surface:
//   env.BUCKET.get(key) -> R2Object with .body / .size / .arrayBuffer()
const RESULTS = {
  // R75: R2Bucket.get() returns a PROMISE (it is async in the Workers runtime).
  // The mock used to be synchronous, which is exactly why the unawaited get()
  // survived so many green runs: `object.body` on a real Promise is undefined
  // and every paid download returns an EMPTY body. Model the real contract.
  async get(key) {
    gets.push(key);
    const bytes = new TextEncoder().encode('PAR1-payload-bytes');
    return {
      key,
      size: bytes.length,
      body: (async function* () { yield bytes; })(),
      async arrayBuffer() { return bytes.buffer; },
      async text() { return 'PAR1-payload-bytes'; },
    };
  },
};

const baseEnv = {
  RESULTS_BUCKET_NAME: 'internal-bucket',
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
  CDP_API_KEY_ID: 'k',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  RUNPOD_ENDPOINT_URL: 'https://fake.upstream', RUNPOD_API_KEY: 'k',
  SECURITY_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => kv.set(k, v) },
  CONSUMED_TX_STORE: {
    idFromName: () => ({ name: 'singleton' }),
    get: () => ({ fetch: async (url, opts) => {
      const p = new URL(url).pathname;
      const j = (o, s = 200) => new Response(JSON.stringify(o), { status: s });
      if (p === '/reserve-nonce' || p === '/release-nonce') return j({ ok: true });
      return j({ ok: true });
    } }),
  },
};

const putReceipt = (over = {}) => {
  const receipt = {
    nonce: NONCE, payer: AUTHZ.from, amountUsdc: 10000,
    bucket: 'internal-bucket', key: 'outputs/paid.parquet',
    settledTx: '0x' + 'cd'.repeat(32), at: Date.now(), ...over,
  };
  kv.set('result:' + NONCE, JSON.stringify(receipt));
  return receipt;
};

const getResult = async (env, query = '') => {
  const ref = encodeURIComponent(JSON.stringify({ key: 'outputs/paid.parquet', bucket: 'internal-bucket' }));
  return gw.fetch(new Request(`https://gw.test/v1/compress/result?${query}&ref=${ref}`,
    { headers: { 'PAYMENT-SIGNATURE': vec.header_b64url } }),
    env, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
};

// --- 1. the source wires the binding and streams (not presigns) ------------
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  ok('a fetchR2Object helper exists', /function fetchR2Object\(/.test(src), 'missing');
  ok('it uses the binding, not hand-rolled signing',
     /bucket\.get\(key\)/.test(src) && !/createPresignedUrl/.test(src),
     'presigning is not a real R2 binding capability');
  // R62: streaming is gated on the receipt naming OUR bucket, not merely on the
  // binding existing -- a BYO receipt must not be looked up in it.
  ok('streaming is gated on the internal bucket name',
     /RESULTS_BUCKET_NAME/.test(src) &&
     /isInternal\s*=/.test(src) &&
     /bucket\.toLowerCase\(\)\s*===\s*internalBucket/.test(src),
     'no internal-bucket gate');
  ok('a BYO bucket is never streamed from the internal binding',
     /!internalBucket \|\| bucket\.toLowerCase\(\) === internalBucket/.test(src),
     'BYO receipts are not excluded');
  // Security-critical ordering: the payer must be proven BEFORE the bytes move.
  // Compare CALL sites, not textual position -- the helper's DEFINITION appears
  // earlier in the file than any call, which is not an ordering violation. Use
  // lastIndexOf for the call so the "fetchR2Object(env, key)" DEFINITION header
  // (which also contains that exact substring) cannot be mistaken for a call.
  const payCall = src.indexOf('recoverPayer(parsedAuth)');
  const fetchCall = src.lastIndexOf('fetchR2Object(env, key)');
  ok('the payer is verified BEFORE the object is fetched',
     payCall > 0 && fetchCall > payCall,
     `payer@${payCall} fetch@${fetchCall}`);
  ok('the fetch happens inside the result endpoint, before the money route',
     fetchCall > src.indexOf("path === '/v1/compress/result'") &&
     fetchCall < src.indexOf("if (request.method !== 'POST'"),
     'fetch is not inside the result endpoint');
  ok('the downloaded filename is sanitized for Content-Disposition',
     /Content-Disposition/.test(src) && /replace\(\/\[\^\\w\./.test(src), 'unsanitized filename');
  ok('responses are not cacheable', /Cache-Control['"]:\s*['"]no-store/.test(src), 'cacheable');

  const cfg = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  ok('wrangler declares the r2_buckets binding', /"r2_buckets"/.test(cfg), 'no binding');
  ok('the binding is named RESULTS', /"binding"\s*:\s*"RESULTS"/.test(cfg), 'wrong name');

  // R51: download_via must be built unconditionally once the identifiers are
  // validated -- NOT gated on the engine returning download_url. A BYO
  // conversion writes to the caller's own bucket and never has one, so those
  // customers were told (in llms.txt / mcp/config) how to fetch their result but
  // the field was missing from the response.
  const dv = src.slice(src.indexOf('body.download_via'),
                       src.indexOf('body.download_via') + 320);
  ok('download_via is assigned unconditionally',
     /^body\.download_via =/.test(dv.trim()) &&
     !/if \(parsed\.download_url\)/.test(dv), 'still gated on download_url');
  ok('download_via points at the authenticated result endpoint',
     /\/v1\/compress\/result\?ref=/.test(dv), 'wrong endpoint');
  ok('it carries only the key and bucket (no presigned URL is relayed)',
     /key:\s*parsed\.output_key/.test(dv) && /bucket:\s*parsed\.output_bucket/.test(dv) &&
     !/download_url/.test(dv), 'a presigned URL may be relayed');
}

// --- 2. a proven payer receives the actual bytes --------------------------
{
  putReceipt();
  gets.length = 0;
  const res = await getResult({ ...baseEnv, RESULTS });
  const ctype = res.headers.get('Content-Type') || '';
  const disp = res.headers.get('Content-Disposition') || '';
  const text = await res.text();
  console.log('payer GET ->', res.status, '|', ctype, '|', disp, '| body:', JSON.stringify(text));

  ok('the payer gets 200', res.status === 200, res.status);
  ok('the object BYTES are returned, not coordinates', text.includes('PAR1-payload-bytes'), text);
  // R75: an unawaited get() yields an EMPTY body. Assert real content, and that
  // production awaits -- the async mock above is what makes this meaningful.
  ok('the downloaded body is NOT empty', text.length > 0, 'empty body');
  ok('the production fetchR2Object AWAITS bucket.get()',
     /const object = await bucket\.get\(key\)/.test(
       readFileSync(new URL('./index.js', import.meta.url), 'utf8')),
     'bucket.get() is not awaited -- every paid download would be empty');
  ok('it is served as parquet', /parquet/.test(ctype), ctype);
  ok('it is an attachment with a sanitized filename',
     /attachment; filename="paid\.parquet"/.test(disp), disp);
  ok('the object was read from the binding', gets.length === 1, gets);
  ok('it is never cached', res.headers.get('Cache-Control') === 'no-store',
     res.headers.get('Cache-Control'));
}

// --- 3. ?meta=1 returns the descriptor without the bytes -----------------
{
  gets.length = 0;
  const res = await getResult({ ...baseEnv, RESULTS }, 'meta=1');
  const body = await res.json();
  console.log('payer meta ->', res.status, JSON.stringify(body).slice(0, 150));
  ok('meta mode returns JSON', res.status === 200 && body.status === 'ready', body);
  ok('meta mode reports the size', typeof body.size === 'number', body.size);
  // R60: download_via must be a CLEAN, parseable URL. It previously appended
  // an English instruction into the query string, so any client parsing it got a
  // malformed link. Assert it parses and that the prose lives elsewhere.
  const dv = body.download_via;
  ok('meta mode returns a download_via URL', typeof dv === 'string' && dv.length > 0, dv);
  let parsedOk = false, parseErr = null;
  try {
    const u = new URL('https://gw.test' + dv);
    const r = u.searchParams.get('ref');
    // the ref must round-trip as JSON, and nothing but real params may be there
    const obj = JSON.parse(r);
    parsedOk = !!obj && obj.key === 'outputs/paid.parquet' && obj.bucket === 'internal-bucket';
    ok('the ref query param round-trips as JSON', parsedOk, r);
    for (const [k, v] of u.searchParams) {
      ok(`query param "${k}" carries no prose`, !/[()]|\bGET\b|\bwith\b/i.test(v), v);
    }
  } catch (e) { parseErr = e.message; }
  ok('download_via parses as a URL with the expected params', parsedOk, parseErr || dv);
  ok('the retrieval instruction is in a separate field',
     typeof body.how_to_retrieve === 'string' &&
     /PAYMENT-SIGNATURE/.test(body.how_to_retrieve), body.how_to_retrieve);
  ok('meta mode does not stream the payload',
     !body.bucket || body.key === 'outputs/paid.parquet', body);
}

// --- 3b. R62: a BYO receipt must NOT be looked up in the internal binding ---
// Regression: routing every receipt through env.RESULTS made BYO jobs 503,
// because their object lives in the CALLER's bucket, not ours.
{
  const BYO_KEY = 'mine/file.parquet';
  const BYO_BUCKET = 'caller-own-bucket';
  putReceipt({ bucket: BYO_BUCKET, key: BYO_KEY });
  const ref = encodeURIComponent(JSON.stringify({ key: BYO_KEY, bucket: BYO_BUCKET }));
  const res = await gw.fetch(new Request(`https://gw.test/v1/compress/result?ref=${ref}`,
    { headers: { 'PAYMENT-SIGNATURE': vec.header_b64url } }),
    { ...baseEnv, RESULTS },                    // binding PRESENT, but wrong bucket
    { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
  const body = await res.json();
  console.log('BYO with R2 binding ->', res.status, JSON.stringify(body).slice(0, 130));
  ok('a BYO receipt resolves even when the R2 binding exists', res.status === 200, res.status);
  ok('it names the CALLER\'s bucket', body.bucket === BYO_BUCKET, body.bucket);
  ok('it states the object is in the caller\'s own bucket',
     typeof body.note === 'string' && /YOUR bucket/.test(body.note), body.note);
}

// --- 4. an unmatched payment gets NOTHING ---------------------------------
{
  gets.length = 0;
  // A different nonce with no receipt.
  const other = Buffer.from(JSON.stringify({
    x402Version: 2,
    payload: { payload: { authorization: { from: '0x' + '11'.repeat(20), nonce: 'ff'.repeat(32) } } },
  })).toString('base64url');
  const res = await gw.fetch(new Request('https://gw.test/v1/compress/result?ref=%7B%7D',
    { headers: { 'PAYMENT-SIGNATURE': other } }),
    { ...baseEnv, RESULTS }, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
  const body = await res.json();
  console.log('unpaid GET ->', res.status, JSON.stringify(body).slice(0, 110));
  ok('an unmatched payment is refused', res.status >= 400, res.status);
  ok('the bucket is never read for an unmatched payment', gets.length === 0, gets);
  ok('no bytes leak in the refusal', !JSON.stringify(body).includes('PAR1'), body);
}

// --- 5. no binding => scoped to the caller's own bucket, no invented link ---
{
  const env = { ...baseEnv };
  delete env.RESULTS;
  const BYO_KEY = 'mine/file.parquet';
  const BYO_BUCKET = 'caller-own-bucket';
  putReceipt({ bucket: BYO_BUCKET, key: BYO_KEY });
  // The ref MUST match the receipt -- the endpoint compares them and 403s on a
  // mismatch (that check is correct and is exercised by result_identifiers_test).
  const ref = encodeURIComponent(JSON.stringify({ key: BYO_KEY, bucket: BYO_BUCKET }));
  const res = await gw.fetch(new Request(`https://gw.test/v1/compress/result?ref=${ref}`,
    { headers: { 'PAYMENT-SIGNATURE': vec.header_b64url } }),
    env, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
  const body = await res.json();
  console.log('no-binding GET ->', res.status, JSON.stringify(body).slice(0, 130));
  ok('a BYO result still resolves', res.status === 200, res.status);
  ok('it does not invent a download_url', body.download_url === undefined, body);
  ok("it states the object is in the caller's own bucket",
     typeof body.note === 'string' && /YOUR bucket/.test(body.note), body.note);
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R46-DELIVERY-FAIL (${fails.length})`
  : 'R46-DELIVERY-ALL-PASS (a proven payer receives the object bytes as a parquet ' +
    'attachment; meta mode returns the descriptor; an unmatched payment reads nothing; ' +
    'without a binding the response stays scoped to the caller\'s own bucket)');
process.exit(fails.length ? 1 : 0);
