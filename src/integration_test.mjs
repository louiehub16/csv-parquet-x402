
import { readFileSync } from 'node:fs';
import gw from './index.js';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8'));
const kvStore = new Map();
const env = {
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',

  // R36: a paid request is refused unless settlement is configured, so tests
  // stub the facilitator (verify+settle return success with a tx hash).
  CDP_API_KEY_ID: 'test-key-id',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  RUNPOD_ENDPOINT_URL: 'https://fake.upstream',
  RUNPOD_API_KEY: 'k',
  SECURITY_KV: { get: async (k) => (kvStore.has(k) ? kvStore.get(k) : null),
                 put: async (k, v) => kvStore.set(k, v) },
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
};
let capturedName = null;
// R21: the AuthorizationUsed log must carry the SAME nonce the settle call saw,
// so the gateway's nonce-bound confirmation can match it.
let lastAuthNonce = '0';
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {  const u0 = String(url);
  if (u0.includes('api.cdp.coinbase.com/platform/v2/x402/verify')) {
    return new Response(JSON.stringify({ isValid: true }), { status: 200 });
  }
  if (u0.includes('api.cdp.coinbase.com/platform/v2/x402/settle')) {
    // R41: echo the settled identity so the proof binds to the authorization.
    let auth = {};
    try { auth = JSON.parse(opts.body).paymentHeader
      ? JSON.parse(Buffer.from(JSON.parse(opts.body).paymentHeader, 'base64url').toString()).payload.authorization
      : {}; } catch (e) {}
    if (auth && auth.nonce) lastAuthNonce = String(auth.nonce);
    return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ab'.repeat(32),
      payer: auth.from, amount: String(auth.value), nonce: auth.nonce, payTo: auth.to }), { status: 200 });
  }

  if (u0.includes('eth_getTransactionReceipt') ||
      (opts && String(opts.body || '').includes('eth_getTransactionReceipt'))) {
    // R21/R23: a real EIP-3009 settle emits
    //   AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)
    // (topic0 0x98de5035..., confirmed against live Base mainnet USDC logs).
    // The confirm step requires that event PLUS a matching-value Transfer, so
    // the fixture emits both. A bare Transfer is (correctly) not sufficient.
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {
      status: '0x1',
      logs: [      { address: '0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913',
        topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          '0x' + '0'*24 + '19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
          '0x795dca28d0e8a0e5d19d689163f125a7da1d0b83'],
        data: '0x' + (10000).toString(16).padStart(64, '0') }
      , { address: '0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913',
        topics: ['0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5',
          '0x' + '0'*24 + '19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
          '0x' + String(lastAuthNonce).replace(/^0x/, ''),
          '0x' + (10000).toString(16).padStart(64, '0')] }]
    } }), { status: 200 });
  }

  // SpendGuard balance preflight hits RunPod GraphQL — return a healthy balance.
  if (String(url).includes('runpod.io/graphql')) {
    return new Response(JSON.stringify({ data: { myself: { balance: 50 } } }), { status: 200 });
  }
  const f = opts.body.get('file');
  capturedName = f.name;
  return new Response(JSON.stringify({ status: 'success', estimated_cost_usd: 0.000001 }), { status: 200 });
};
try {
  const fd = new FormData();
  fd.append('file', new File([new TextEncoder().encode('a,b\n1,2\n3,4\n')], 'tiny.csv'));
  const req = new Request('https://gw.test/v1/compress', {
    method: 'POST', body: fd,
    headers: { 'PAYMENT-SIGNATURE': vec.header_b64url },
  });
  const r = await gw.fetch(req, env, { waitUntil(p) { if (p && p.catch) p.catch(()=>{}); } });
  const body = await r.json();
  console.log('gateway status:', r.status);
  console.log('upstream filename:', capturedName);
  console.log('output_key style:', JSON.stringify(body).slice(0,120));
  if (r.status !== 200) console.log('DIAG note:', body.note || body.error);
  if (r.status !== 200) process.exit(1);
  if (!/\.(csv|tsv|txt)$/.test(capturedName)) { console.log('FATAL: non-input extension forwarded:', capturedName); process.exit(1); }
  console.log('INTEGRATION-PASS');
  process.exit(0);
} finally {
  globalThis.fetch = realFetch;
}
