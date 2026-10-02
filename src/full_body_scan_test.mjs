// R45 regression test: the binary/NUL scan must cover the WHOLE body.
//
// BUG: both layers sniffed only the first 1 MiB -- the gateway in gate (5) and
// the engine in its own "defense in depth" guard read exactly 1048576 bytes.
// A NUL byte or embedded archive magic PAST that boundary therefore reached PAID
// processing, so a customer could be charged to "convert" a binary payload.
//
// The gateway already buffers the whole upload in memory (formData()), so the
// full-body scan costs one pass over bytes already held. This drives the real
// gateway and asserts a NUL past the 1 MiB boundary is refused.
import { readFileSync } from 'node:fs';
import gw from './index.js';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf8'));
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- the source must scan the full body, not just the 1 MiB prefix ---
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  ok('a full-body scan exists (file.arrayBuffer, not a prefix slice)',
     /await file\.arrayBuffer\(\)/.test(src), 'no full-body read');
  // R64 added a full-body UTF-8 validation block ahead of this one, so
  // anchor on the (5.1) scan specifically rather than the first match.
  const scan = src.indexOf('FULL-BODY BINARY SCAN');
  const i = src.indexOf('await file.arrayBuffer()', scan);
  const block = src.slice(i, i + 1400);
  ok('it scans every byte for NUL, not just the head',
     /for \(let i = 0; i < all\.length; i\+\+\)/.test(block) && /all\[i\] === 0x00/.test(block),
     'no whole-buffer NUL scan');
  ok('it scans for archive magic at the FILE START (offset 0 / after a BOM)',
     /const magic = \(i\) =>/.test(block) && /magic\(m\)/.test(block),
     'no start-of-file magic check');
  // R50: magic must NOT be searched across the whole body -- that rejected
  // legitimate CSV containing "PK" or "%PD" in a cell.
  ok('it does NOT scan the whole body for magic (that rejected real CSVs)',
     !/for \(let i = 0; i \+ 1 < all\.length; i\+\+\)/.test(block),
     'whole-body magic scan is back');
  ok('a UTF-8 BOM is skipped before the magic check',
     /0xef && all\[1\] === 0xbb && all\[2\] === 0xbf/.test(block), 'BOM not handled');
  ok('a NUL anywhere still returns null_byte_detected',
     /null_byte_detected/.test(block), 'missing error');
  ok('embedded magic returns archive_or_binary_detected',
     /archive_or_binary_detected/.test(block), 'missing error');
}

// --- behavioural: drive the real gateway with a NUL past the 1 MiB boundary ---
{
  const kv = new Map();
  const env = {
    MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
    CDP_API_KEY_ID: 'k',
    CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
    RUNPOD_ENDPOINT_URL: 'https://fake.upstream', RUNPOD_API_KEY: 'k',
    SECURITY_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => kv.set(k, v) },
    CONSUMED_TX_STORE: {
      idFromName: () => ({ name: 'singleton' }),
      get: () => ({ fetch: async (url, opts) => {
        const p = new URL(url).pathname;
        const b = opts && opts.body ? JSON.parse(opts.body) : {};
        const j = (o, s = 200) => new Response(JSON.stringify(o), { status: s });
        if (p === '/reserve-nonce') return j({ ok: true });
        if (p === '/release-nonce') return j({ ok: true });
        if (p === '/reserve-budget') return j({ ok: true });
        if (p === '/budget') return j({ ok: true, date: new Date().toISOString().slice(0, 10), total: 0 });
        return j({ ok: true });
      } }),
    },
  };

  const run = async (bytes, label) => {
    const fd = new FormData();
    fd.append('file', new File([bytes], 'big.csv'));
    const r = await gw.fetch(
      new Request('https://gw.test/v1/compress', {
        method: 'POST', body: fd, headers: { 'PAYMENT-SIGNATURE': vec.header_b64url },
      }), env, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
    return { status: r.status, body: await r.json() };
  };

  // A well-formed 1.5 MB CSV, with a NUL planted PAST the 1 MiB boundary.
  const size = 1024 * 1024 + 512 * 1024;
  const clean = new Uint8Array(size);
  const line = new TextEncoder().encode('a,b,c\n1,2,3\n');
  for (let i = 0; i < size; i++) clean[i] = line[i % line.length];
  const withNul = Uint8Array.from(clean);
  withNul[size - 1024] = 0x00;                    // beyond 1 MiB
  console.log('NUL planted at byte', size - 1024, '(1 MiB =', 1048576, ')');

  const nulRes = await run(withNul, 'nul past 1 MiB');
  console.log('NUL past 1 MiB  ->', nulRes.status, JSON.stringify(nulRes.body).slice(0, 90));
  ok('a NUL past the 1 MiB boundary is REFUSED', nulRes.status === 400, nulRes.status);
  ok('it reports null_byte_detected', nulRes.body.error === 'null_byte_detected', nulRes.body);

  // A clean large CSV must still pass the binary gate (no false positive).
  const cleanRes = await run(clean, 'clean large csv');
  console.log('clean 1.5 MB    ->', cleanRes.status, JSON.stringify(cleanRes.body).slice(0, 90));
  ok('a clean 1.5 MB CSV is NOT rejected as binary',
     cleanRes.body.error !== 'null_byte_detected' &&
     cleanRes.body.error !== 'archive_or_binary_detected', cleanRes.body);

  // R50: magic bytes ANYWHERE IN THE BODY must not reject legitimate data. A CSV
  // cell containing "PK", a product code starting "%PD", or a gzip-looking pair
  // is ordinary text; the earlier whole-body magic scan refused all of it.
  for (const [needle, label] of [
    ['PK', 'literal PK in a cell'],
    ['%PDF', 'product code starting %PD'],
    ['\x1f\x8b', 'gzip-looking byte pair'],
    ['PK\x03\x04zipstuff', 'an embedded zip local-file header'],
  ]) {
    const withText = Uint8Array.from(clean);
    const nBytes = new TextEncoder().encode(needle);
    // plant it well past the 1 MiB boundary and past the head
    withText.set(nBytes, 1024 * 1024 + 2048);
    const r = await run(withText, label);
    console.log(`${label.padEnd(34)}->`, r.status, JSON.stringify(r.body).slice(0, 60));
    ok(`${label} is accepted (not treated as an archive)`,
       r.body.error !== 'archive_or_binary_detected', r.body);
  }
  // ...but a file that ACTUALLY IS a zip must still be refused.
  {
    const zip = new Uint8Array(4096);
    zip.set([0x50, 0x4b, 0x03, 0x04], 0);
    const r = await run(zip, 'real zip');
    console.log('real zip                 ->', r.status, JSON.stringify(r.body).slice(0, 60));
    ok('a genuine archive is still rejected',
       r.body.error === 'archive_or_binary_detected' || r.status === 400, r.body);
  }
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R45-FULLSCAN-FAIL (${fails.length})`
  : 'R45-FULLSCAN-ALL-PASS (whole-body NUL + embedded-magic scan; a NUL past the 1 MiB ' +
    'boundary is refused; a clean 1.5 MB CSV still passes)');
process.exit(fails.length ? 1 : 0);
