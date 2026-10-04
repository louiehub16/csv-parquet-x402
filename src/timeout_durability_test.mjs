// R25 regression test: post-settlement timeout must leave DURABLE state.
//
// BUG: the timeout path returned 504 with refund:'not_applicable' and recorded
// nothing. The only trace was an in-memory flag that died with the isolate, so
// when a SETTLED payer's conversion timed out there was no sweepable state and
// collected funds could sit stranded with nothing pointing at them.
//
// This drives the REAL gateway (default export) through a settled payment whose
// upstream hangs, and asserts on the observable KV state and HTTP body. It is a
// behavioural test, not a source-text match.
import { readFileSync } from 'node:fs';
import gw from './index.js';

// Read the vector LAZILY: mint_vector.py refreshes the authorization time
// window, and an import-time read captured a stale/expired vector (which
// failed as time_window_violation and looked like a gateway bug).
let vec = null;
const getVec = () => (vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8')));
const kv = new Map();
const env = {
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
  UPSTREAM_TIMEOUT_MS: '25',   // compress OUR gateway timeout (R79)
  CDP_API_KEY_ID: 'k', CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  RUNPOD_ENDPOINT_URL: 'https://fake.upstream', RUNPOD_API_KEY: 'k',
  SECURITY_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null), put: async (k, v) => kv.set(k, v) },
  CONSUMED_TX_STORE: (() => {
    const nonces = new Set(), refunds = new Map();
    let daily = 0;
    const id = { name: 'singleton' };
    return { idFromName: () => id, get: () => ({ fetch: async (_u, o) => {
      const p = new URL(_u).pathname, b = o.body ? JSON.parse(o.body) : {};
      const j = (x, s = 200) => new Response(JSON.stringify(x), { status: s });
      if (p === '/reserve-budget') { daily += b.amountUsd || 0; return j({ ok: true, newTotal: daily }); }
      if (p === '/budget') return j({ ok: true, date: new Date().toISOString().slice(0, 10), total: daily });
      if (p === '/reserve-nonce') return nonces.has(b.nonce) ? j({ ok: false, already: 'used' }, 409) : (nonces.add(b.nonce), j({ ok: true }));
      if (p === '/release-nonce') { nonces.delete(b.nonce); return j({ ok: true }); }
      if (p === '/claim-refund') { const a = refunds.has(b.nonce); refunds.set(b.nonce, false); return j({ ok: true, claimed: !a }); }
      if (p === '/mark-refunded') { refunds.set(b.nonce, true); return j({ ok: true }); }
      return j({ ok: true });
    } }) };
  })(),
};

let lastAuthNonce = '0';
let abortNow = () => {};
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const u0 = String(url);
  if (u0.includes('/x402/verify')) return new Response(JSON.stringify({ isValid: true }), { status: 200 });
  if (u0.includes('/x402/settle')) {
    let auth = {};
    try { auth = JSON.parse(Buffer.from(JSON.parse(opts.body).paymentHeader, 'base64url').toString()).payload.authorization; } catch (e) {}
    if (auth && auth.nonce) lastAuthNonce = String(auth.nonce);
    return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ab'.repeat(32),
      payer: auth.from, amount: String(auth.value), nonce: auth.nonce, payTo: auth.to }), { status: 200 });
  }
  if (u0.includes('mainnet.base.org') || u0.includes('eth_getTransactionReceipt')) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: '0x1', logs: [
      { address: '0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913',
        topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
          '0x' + '0'*24 + '19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
          '0x795dca28d0e8a0e5d19d689163f125a7da1d0b83'],
        data: '0x' + (10000).toString(16).padStart(64, '0') },
      { address: '0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913',
        topics: ['0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5',
          '0x' + '0'*24 + '19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
          '0x' + String(lastAuthNonce).replace(/^0x/, '')] },
    ] } }), { status: 200 });
  }
  if (u0.includes('runpod.io/graphql')) return new Response(JSON.stringify({ data: { myself: { balance: 50 } } }), { status: 200 });
  // Real dispatch reached: trip the request abort so the gateway's AbortController
  // fires exactly as its own 10-minute timer eventually would.
  if (u0.includes('fake.upstream')) {
    // No abort here: the gateway's OWN timer fires (UPSTREAM_TIMEOUT_MS is set
    // to a few ms below). This is the only way to exercise the real timeout path
    // now that a client-signal abort is correctly treated as a disconnect.
  }
  // Upstream accepts the job then stalls. Behave like a real fetch: honour the
  // AbortSignal, so the gateway's own AbortController drives the timeout path.
  return new Promise((_res, rej) => {
    const sig = opts && opts.signal;
    const fail = () => { const e = new Error('aborted'); e.name = 'AbortError'; rej(e); };
    if (!sig) return;                        // nothing to honour
    if (sig.aborted) return fail();
    sig.addEventListener('abort', fail, { once: true });
  });
};

const fails = [];
try {
  const fd = new FormData();
  fd.append('file', new File([new TextEncoder().encode('a,b\n1,2\n')], 'tiny.csv'));
  const req = new Request('https://gw.test/v1/compress', { method: 'POST', body: fd,
    headers: { 'PAYMENT-SIGNATURE': getVec().header_b64url } });
  // R79: NO request signal is supplied. A client-supplied signal that aborts is a
  // CLIENT DISCONNECT and now (correctly) takes the refund path; to exercise OUR
  // controller timeout, the only abort source must be the gateway's own -- which
  // the upstream stub trips below, exactly as its setTimeout would.
  const r = await Promise.race([
    gw.fetch(req, env,   // no client signal: the gateway's controller is the only abort source
      { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } }),
    new Promise((res) => setTimeout(() => res(null), 8000)),
  ]);
  if (!r) { console.log('FAIL: gateway never settled after the upstream timeout'); process.exit(1); }
  const body = await r.json();
  console.log('timeout status:', r.status, '| body:', JSON.stringify(body).slice(0, 160));
  if (r.status !== 504) {
    fails.push(`expected 504 gateway_timeout, got ${r.status}` +
      ` [note=${JSON.stringify(body.note)} statusNote=${JSON.stringify(body.statusNote)}]`);
  }
  if (body.error !== 'gateway_timeout') fails.push(`error should be gateway_timeout, got ${body.error}`);
  if (body.refund === 'not_applicable' && body.settled_collected !== false) {
    fails.push('reported not_applicable while a payment had been collected');
  }

  // The decisive assertion: a durable, sweepable record exists for the nonce.
  const keys = [...kv.keys()];
  const tKeys = keys.filter((k) => k.startsWith('timeout:'));
  console.log('KV keys after timeout:', JSON.stringify(keys));
  if (!tKeys.length) fails.push('no durable timeout record was written (funds can strand)');

  for (const k of tKeys) {
    const rec = JSON.parse(kv.get(k));
    console.log('durable record:', k, '->', JSON.stringify(rec).slice(0, 200));
    if (!rec.nonce) fails.push('record missing nonce');
    if (typeof rec.settled !== 'boolean') fails.push('record does not say whether payment was collected');
    if (rec.status !== 'awaiting_reconciliation') fails.push(`unexpected status ${rec.status}`);
    if (!rec.payer) fails.push('record missing payer for reconciliation');
  }
} finally {
  globalThis.fetch = realFetch;
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `TIMEOUT-DURABILITY-FAIL (${fails.length})`
  : 'TIMEOUT-DURABILITY-ALL-PASS (durable nonce-keyed reconciliation claim after a settled timeout)');
process.exit(fails.length ? 1 : 0);