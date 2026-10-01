// R49 regression test: a transport failure must not lock the payer out.
//
// BUG: five cleanup sites released the nonce claim on the condition
// `!upstreamDispatched`, but `upstreamDispatched = true` is set a few lines ABOVE
// each of them -- so the condition was ALWAYS false and the Durable Object claim
// survived every transport error, timeout and internal error. The payer could
// never retry that authorization: a permanent lockout on a request that never
// reached the engine.
//
// The fix separates the two facts: `upstreamDispatched` = attempted (drives the
// conservative BUDGET reconciliation), `upstreamAccepted` = the engine responded
// (the only point at which compute is known to have run, and therefore the only
// point at which the claim must be retained).
//
// This drives the REAL gateway with an upstream that never responds.
import { readFileSync } from 'node:fs';
import gw from './index.js';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8'));
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- 1. source invariants -------------------------------------------------
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  ok('an upstreamAccepted flag exists', /let upstreamAccepted = false;/.test(src), 'missing');
  ok('it is set only once the engine RESPONDS',
     /upstreamAccepted = true;/.test(src) &&
     src.indexOf('upstreamAccepted = true;') > src.indexOf('upstream = await fetch('),
     'not set after the fetch resolves');
  ok('dispatched is still recorded separately',
     /upstreamDispatched = true;/.test(src), 'dispatch tracking lost');

  // Every NONCE-release site must key off upstreamAccepted. A release guarded by
  // `!upstreamDispatched` is unreachable and is a lockout.
  const releaseRe = /if \(env\.CONSUMED_TX_STORE && v && v\.nonce && !paymentSettled && !(\w+)\)/g;
  const sites = [...src.matchAll(releaseRe)].map((m) => m[1]);
  ok('there are nonce-release sites to check', sites.length >= 5, `${sites.length} found`);
  ok('EVERY release site is guarded by upstreamAccepted',
     sites.every((f) => f === 'upstreamAccepted'),
     `guards: ${[...new Set(sites)].join(', ')}`);

  // The BUDGET site must keep the conservative flag: an attempt may have burned
  // compute, so the reservation is not released to $0 there.
  ok('the budget site keeps the conservative upstreamDispatched guard',
     /budgetTxId && !upstreamDispatched/.test(src), 'budget guard was changed');
}

// --- 2. behavioural: an unreachable engine must release the claim ---------
{
  const doCalls = [];
  const kv = new Map();
  const env = {
    MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
    CDP_API_KEY_ID: 'k',
    CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
    RUNPOD_ENDPOINT_URL: 'https://fake.upstream', RUNPOD_API_KEY: 'k',
    SECURITY_KV: { get: async (k) => (kv.has(k) ? kv.get(k) : null),
                   put: async (k, v) => kv.set(k, v), delete: async (k) => kv.delete(k) },
    CONSUMED_TX_STORE: {
      idFromName: () => ({ name: 'singleton' }),
      get: () => ({ fetch: async (url, opts) => {
        const p = new URL(url).pathname;
        const b = opts && opts.body ? JSON.parse(opts.body) : {};
        doCalls.push(p);
        const j = (o, s = 200) => new Response(JSON.stringify(o), { status: s });
        if (p === '/reserve-nonce') return j({ ok: true });
        if (p === '/release-nonce') return j({ ok: true, released: true });
        if (p === '/reserve-budget') return j({ ok: true });
        if (p === '/budget') return j({ ok: true, date: new Date().toISOString().slice(0, 10), total: 0 });
        return j({ ok: true });
      } }),
    },
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/x402/verify')) return new Response(JSON.stringify({ isValid: true }), { status: 200 });
    if (u.includes('/x402/settle')) {
      return new Response(JSON.stringify({ success: false, error: 'invalid payment amount' }),
        { status: 200 });
    }
    if (u.includes('runpod.io/graphql')) {
      return new Response(JSON.stringify({ data: { myself: { balance: 50 } } }), { status: 200 });
    }
    if (u.includes('mainnet.base.org') || u.includes('eth_getTransactionReceipt')) {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { status: '0x1', logs: [] } }),
        { status: 200 });
    }
    if (u.includes('fake.upstream')) throw new Error('simulated network failure');
    throw new Error('unexpected fetch: ' + u);
  };

  let status = null, body = null;
  try {
    const fd = new FormData();
    fd.append('file', new File([new TextEncoder().encode('a,b\n1,2\n')], 'tiny.csv'));
    const r = await gw.fetch(new Request('https://gw.test/v1/compress', {
      method: 'POST', body: fd, headers: { 'PAYMENT-SIGNATURE': vec.header_b64url },
    }), env, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
    status = r.status;
    body = await r.json().catch(() => null);
    // give any background release a tick
    await new Promise((res) => setTimeout(res, 30));
  } finally {
    globalThis.fetch = realFetch;
  }

  const releases = doCalls.filter((c) => c === '/release-nonce');
  console.log('gateway status   :', status, '|', JSON.stringify(body).slice(0, 110));
  console.log('DO calls        :', JSON.stringify([...new Set(doCalls)]));
  console.log('release-nonce   :', releases.length);

  ok('the request failed rather than being served', status >= 400, status);
  ok('the nonce was CLAIMED before dispatch',
     doCalls.includes('/reserve-nonce'), 'no claim was taken');
  // NOTE: this runtime assertion alone does NOT isolate R49 -- the surrounding
  // catch-all has its own release path, so a release is observed even with the
  // per-site guard reverted. The source assertions in sections 1 and 3 are what
  // actually pin the fix; this one only asserts the end state is not a lockout.
  ok('a release was issued (end state is not a lockout)', releases.length >= 1,
     'no release-nonce issued');
  ok('a release is not spammed (idempotent, bounded)', releases.length <= 4,
     `${releases.length} releases`);
}

// --- 3. the pre-fix shape must be detectable -----------------------------
{
  const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  ok('no release site still keys off the attempt flag (the R49 lockout)',
     !/!paymentSettled && !upstreamDispatched\)/.test(src),
     'a release site still uses upstreamDispatched');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R49-CLAIM-RELEASE-FAIL (${fails.length})`
  : 'R49-CLAIM-RELEASE-ALL-PASS (an engine that never responds releases the DO nonce ' +
    'claim so the payer can retry; the budget path keeps its conservative guard)');
process.exit(fails.length ? 1 : 0);
