// Gateway smoke: exercises real fetch() paths with Node-native Request/FormData.
import gw from './index.js';

const kvStore = new Map();
const env = {
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',

  // R36: a paid request is refused unless settlement is configured, so tests
  // stub the facilitator (verify+settle return success with a tx hash).
  CDP_API_KEY_ID: 'test-key-id',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  RUNPOD_ENDPOINT_URL: 'https://fake.runpod.test',
  RUNPOD_API_KEY: 'fake-key',
  SG_MAX_JOB_COST: '0.50',
  SG_CPU_RATE_PER_HR: '0.13',
  SECURITY_KV: {
    get: async (k) => (kvStore.has(k) ? kvStore.get(k) : null),
    put: async (k, v) => { kvStore.set(k, v); },
  },
  // SpendGuard DO stub: atomic budget ledger. Accepts reserve/reset calls,
  // tracks spend, enforces the cap the same way the real ConsumedTxStore does.
  CONSUMED_TX_STORE: (() => {
    let daily = 0;
  const refunds = new Map();
    const nonces = new Set();
    const id = { name: 'singleton' };
    return {
      idFromName: () => id,
      get: () => ({
                fetch: async (_url, opts) => {
          const path = new URL(_url).pathname;
          const body = opts.body ? JSON.parse(opts.body) : {};
          if (opts.method === 'POST' && path === '/reserve-budget') {
            const cap = body.capUsd ?? 50;
            if (daily + body.amountUsd > cap) {
              return new Response(JSON.stringify({ ok: false, already: 'daily_cap_reached' }), { status: 503 });
            }
            daily += body.amountUsd;
            return new Response(JSON.stringify({ ok: true, newTotal: daily }), { status: 200 });
          }
          if (opts.method === 'GET' && path === '/budget') {
            const today = new Date().toISOString().slice(0, 10);
            return new Response(JSON.stringify({ ok: true, date: today, total: daily }), { status: 200 });
          }
          if (opts.method === 'POST' && path === '/claim-refund') {
            if (refunds.has(body.nonce)) return new Response(JSON.stringify({ ok: true, alreadyRefunded: refunds.get(body.nonce) }), { status: 200 });
            refunds.set(body.nonce, false);
            return new Response(JSON.stringify({ ok: true, claimed: true }), { status: 200 });
          }
          if (opts.method === 'POST' && path === '/mark-refunded') {
            refunds.set(body.nonce, true);
            return new Response(JSON.stringify({ ok: true, refunded: true }), { status: 200 });
          }
          if (opts.method === 'POST' && path === '/reserve-nonce') {
            if (nonces.has(body.nonce)) {
              return new Response(JSON.stringify({ ok: false, already: 'used' }), { status: 409 });
            }
            nonces.add(body.nonce);
            return new Response(JSON.stringify({ ok: true }), { status: 200 });
          }
          if (opts.method === 'POST' && path === '/finalize-nonce') {
            if (nonces.has(body.nonce)) {
              return new Response(JSON.stringify({ ok: true, finalized: true }), { status: 200 });
            }
            return new Response(JSON.stringify({ ok: false, error: 'nonce_not_claimed' }), { status: 409 });
          }
          if (opts.method === 'POST' && path === '/reset-budget') {
            daily = 0;
            return new Response(JSON.stringify({ ok: true }), { status: 200 });
          }
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        },

      }),
      __spend: () => daily,
    };
  })(),
  ASSETS: { fetch: async () => new Response('# fake asset', { status: 200 }) },
};
const ctx = { waitUntil: (_p) => {} };
let fails = 0;
const check = (n, c, x = '') => { console.log((c ? 'PASS ' : 'FAIL ') + n + (x ? ` [${x}]` : '')); if (!c) fails++; };

// 1. health
// R53: the gateway now checks upstream balance BEFORE payment and confirms the
// settled transfer on-chain, so the smoke test must mock those upstreams.
globalThis.fetch = async (url, opts) => {
  const u0 = String(url);
  const bodyTxt = opts ? String(opts.body || '') : '';
  if (u0.includes('runpod.io/graphql')) {
    return new Response(JSON.stringify({ data: { myself: { balance: 50 } } }), { status: 200 });
  }
  if (u0.includes('x402/verify')) {
    return new Response(JSON.stringify({ isValid: true }), { status: 200 });
  }
  if (u0.includes('x402/settle')) {
    let auth = {};
    try {
      const b = JSON.parse(bodyTxt);
      auth = JSON.parse(Buffer.from(b.paymentHeader, 'base64url').toString()).payload.authorization;
    } catch (e) {}
    return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ab'.repeat(32),
      payer: auth.from, payTo: auth.to, amount: String(auth.value), nonce: auth.nonce }), { status: 200 });
  }
  if (bodyTxt.includes('eth_getTransactionReceipt')) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: '0x1',
      logs: [{ address: '0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913',
        topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          '0x' + '0'.repeat(24) + '19e7e376e7c213b7e7e7e46cc70a5dd086daffa2',
          '0x795dca28d0e8a0e5d19d689163f125a7da1d0b83'],
        data: '0x' + (10000).toString(16).padStart(64, '0') }] } }), { status: 200 });
  }
  return new Response(JSON.stringify({ status: 'success', estimated_cost_usd: 0.000001 }), { status: 200 });
};

let r = await gw.fetch(new Request('https://gw.test/health'), env, ctx);
check('GET /health 200', r.status === 200);

// 2. landing
r = await gw.fetch(new Request('https://gw.test/'), env, ctx);
check('GET / 200 html', r.status === 200 && (await r.text()).includes('CSV-to-Parquet'));

// 3. discovery passthrough
r = await gw.fetch(new Request('https://gw.test/llms.txt'), env, ctx);
check('GET /llms.txt via ASSETS', r.status === 200);

// 4. money route, no payment -> exact-price 402 challenge
{
  const fd = new FormData();
  fd.append('file', new File([new TextEncoder().encode('a,b\n1,2\n3,4\n')], 'tiny.csv'));
  r = await gw.fetch(new Request('https://gw.test/v1/compress', { method: 'POST', body: fd }), env, ctx);
  const manifest = r.headers.get('PAYMENT-REQUIRED');
  check('POST no-pay -> 402', r.status === 402, String(r.status));
  check('PAYMENT-REQUIRED header present', !!manifest);
  let m;
  try { m = JSON.parse(Buffer.from(manifest, 'base64url').toString()); } catch (e) {}
  check('manifest parses, amount=10000 (tiny file flat $0.01)', m?.accepts?.[0]?.amount === '10000');
  check('manifest payTo = merchant wallet', m?.accepts?.[0]?.payTo === env.MERCHANT_WALLET_ADDRESS);
}

// 5. bad extension rejected pre-payment
{
  const fd = new FormData();
  fd.append('file', new File([new TextEncoder().encode('MZ')], 'evil.exe'));
  r = await gw.fetch(new Request('https://gw.test/v1/compress', { method: 'POST', body: fd }), env, ctx);
  check('.exe rejected 400', r.status === 400);
}

// 6. archive magic rejected (REAL binary this time — Uint8Array)
{
  const fd = new FormData();
  const bin = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
  fd.append('file', new File([bin], 'zipped.csv'));
  r = await gw.fetch(new Request('https://gw.test/v1/compress', { method: 'POST', body: fd }), env, ctx);
  check('PK zip magic rejected 400', r.status === 400, `${r.status} ${await r.text().then(t=>t.slice(0,60))}`);
}

// 6b. NUL byte in real binary rejected
{
  const fd = new FormData();
  fd.append('file', new File([new Uint8Array([0x61, 0x00, 0x62, 0x0a])], 'nul.csv'));
  r = await gw.fetch(new Request('https://gw.test/v1/compress', { method: 'POST', body: fd }), env, ctx);
  check('NUL byte rejected 400', r.status === 400);
}

// NOTE: the >=10GB BYO-storage rule cannot be exercised through a real encoded
// request without an actual 10 GB payload (undici derives file.size from the
// encoded bytes). Covered by direct inspection of gate (4):
//   size >= 10*GB && !target_destination -> 400 byo_storage_required.
console.log(fails === 0 ? 'GW-SMOKE-ALL-PASS' : `GW-SMOKE FAILURES: ${fails}`);
process.exit(fails === 0 ? 0 : 1);
