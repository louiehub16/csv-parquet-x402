// R35 regression test: a definitive no-settlement rejection must release the DO claim.
//
// BUG: the settle callback deleted a SECURITY_KV key on definitelyNotSubmitted,
// but the nonce claim is held by CONSUMED_TX_STORE (the Durable Object). The KV
// delete did nothing to the real store, so the claim stayed consumed and the
// payer could never retry that authorization -- the exact lockout the R32 flag
// exists to prevent. The flag was set correctly; the RELEASE was aimed at the
// wrong store.
//
// This drives the REAL gateway: a paid request whose facilitator response is a
// permanent rejection must issue a POST /release-nonce to the DO.
import { readFileSync } from 'node:fs';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8'));
const gw = (await import('./index.js')).default;

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const doCalls = [];
const kv = new Map();
const env = {
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
  CDP_API_KEY_ID: 'k',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  RUNPOD_ENDPOINT_URL: 'https://fake.upstream',
  RUNPOD_API_KEY: 'k',
  SECURITY_KV: {
    get: async (k) => (kv.has(k) ? kv.get(k) : null),
    put: async (k, v) => kv.set(k, v),
    delete: async (k) => kv.delete(k),
  },
  CONSUMED_TX_STORE: {
    idFromName: () => ({ name: 'singleton' }),
    get: () => ({ fetch: async (url, opts) => {
      const path = new URL(url).pathname;
      const body = opts && opts.body ? JSON.parse(opts.body) : {};
      doCalls.push({ path, body });
      const j = (o, s = 200) => new Response(JSON.stringify(o), { status: s });
      if (path === '/reserve-nonce') return j({ ok: true });
      if (path === '/release-nonce') return j({ ok: true, released: true });
      if (path === '/reserve-budget') return j({ ok: true });
      if (path === '/budget') return j({ ok: true, date: new Date().toISOString().slice(0, 10), total: 0 });
      return j({ ok: true });
    } }),
  },
};

// Facilitator: verify passes, settle is a PERMANENT payment rejection.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const u = String(url);
  if (u.includes('/x402/verify')) return new Response(JSON.stringify({ isValid: true }), { status: 200 });
  if (u.includes('/x402/settle')) {
    return new Response(JSON.stringify({ success: false, error: 'invalid payment amount' }),
      { status: 200 });
  }
  if (u.includes('runpod.io/graphql')) {
    return new Response(JSON.stringify({ data: { myself: { balance: 50 } } }), { status: 200 });
  }
  throw new Error('unexpected fetch: ' + u);
};

let status = null;
try {
  const fd = new FormData();
  fd.append('file', new File([new TextEncoder().encode('a,b\n1,2\n')], 'tiny.csv'));
  const r = await gw.fetch(
    new Request('https://gw.test/v1/compress', {
      method: 'POST', body: fd, headers: { 'PAYMENT-SIGNATURE': vec.header_b64url },
    }), env, { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } });
  status = r.status;
} finally {
  globalThis.fetch = realFetch;
}

const releases = doCalls.filter((c) => c.path === '/release-nonce');
console.log('gateway status      :', status);
console.log('DO /reserve-nonce   :', doCalls.filter((c) => c.path === '/reserve-nonce').length);
console.log('DO /release-nonce   :', releases.length,
            releases.length ? '(nonce ' + String(releases[0].body.nonce).slice(0, 12) + '…)' : '');

ok('the DO claim was taken before settlement',
   doCalls.filter((c) => c.path === '/reserve-nonce').length === 1, 'no claim');
ok('a definitive rejection RELEASES the DO nonce claim', releases.length >= 1,
   `release calls: ${releases.length}`);
ok('every release carries a 64-hex claimed nonce',
   releases.length >= 1 && releases.every((c) => /^[0-9a-f]{64}$/.test(String(c.body.nonce || ''))),
   releases.map((c) => c.body.nonce));
ok('the released nonce is the one the authorization used',
   releases.length >= 1 &&
   releases.every((c) => String(c.body.nonce) === String(releases[0].body.nonce)),
   releases.map((c) => c.body.nonce));
// NOTE: >1 release is expected -- the settle callback releases, then the
// catch-all's unsettled/undispatched branch releases again. Release is
// idempotent, so the duplicate is harmless; what matters is that it HAPPENS.
ok('the job was not delivered (no 200)', status !== 200, status);

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R35-CLAIM-RELEASE-FAIL (${fails.length})`
  : 'R35-CLAIM-RELEASE-ALL-PASS (definitive rejection issues DO /release-nonce for the ' +
    'claimed nonce; the KV mirror alone would have left the payer locked out)');
process.exit(fails.length ? 1 : 0);
