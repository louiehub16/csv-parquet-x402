// R32 regression test: a PROVEN no-settlement rejection must release the nonce.
//
// BUG: cdpVerifyAndSettle() returned ok:false WITHOUT definitelyNotSubmitted on
// three proven-no-money-moved paths:
//   - verify returns a permanent (payment-domain) HTTP rejection
//   - verify returns 2xx with a payment-phase rejection reason
//   - settle returns 2xx-without-success naming a payment rejection
// The gateway releases the Durable Object claim ONLY on that exact flag
// (x402.js -> releaseNonceClaim), so those paths left the claim standing and
// locked the payer out of an authorization the facilitator never took.
//
// This drives the REAL cdpVerifyAndSettle() against a stubbed facilitator and
// asserts the flag is present on those outcomes -- and absent on the ambiguous
// ones, where retaining the claim is the correct behaviour.
import { readFileSync } from 'node:fs';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8'));
const { cdpVerifyAndSettle } = await import('./cdp.js');

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const env = {
  CDP_API_KEY_ID: 'test-key-id',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
};

const decoded = JSON.parse(Buffer.from(vec.header_b64url, 'base64url').toString());
const headerB64 = Buffer.from(
  JSON.stringify({ ...decoded, payload: { ...decoded.payload } }), 'utf8').toString('base64url');

const call = async (verifyRes, settleRes) => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/x402/verify')) return verifyRes;
    if (u.includes('/x402/settle')) return settleRes;
    throw new Error('unexpected ' + u);
  };
  try {
    return await cdpVerifyAndSettle(env, headerB64, 'csv-parquet-stream-compressor', 10000, 10000);
  } finally { globalThis.fetch = realFetch; }
};

const js = (o, status) => new Response(JSON.stringify(o), { status });

// --- PROVEN no settlement: the flag MUST be set ---

// 1. verify -> permanent payment rejection (402).
{
  const r = await call(js({ error: 'invalid payment amount' }, 402),
                       js({ error: 'should not be reached' }, 500));
  console.log('verify 402       ->', JSON.stringify({ ok: r.ok, dns: r.definitelyNotSubmitted, reason: r.reason }));
  ok('verify 402 sets definitelyNotSubmitted', r.definitelyNotSubmitted === true, r);
}

// 2. verify -> 2xx with a payment-phase rejection reason.
{
  const r = await call(js({ isValid: false, error: 'invalid payment nonce' }, 200),
                       js({ error: 'should not be reached' }, 500));
  console.log('verify invalid   ->', JSON.stringify({ ok: r.ok, dns: r.definitelyNotSubmitted, reason: r.reason }));
  ok('verify 2xx rejection sets definitelyNotSubmitted', r.definitelyNotSubmitted === true, r);
}

// 3. settle -> 2xx without success, naming a payment rejection.
{
  const r = await call(js({ isValid: true }, 200),
                       js({ success: false, error: 'invalid payment amount' }, 200));
  console.log('settle rejection ->', JSON.stringify({ ok: r.ok, dns: r.definitelyNotSubmitted, reason: r.reason }));
  ok('settle 2xx rejection sets definitelyNotSubmitted', r.definitelyNotSubmitted === true, r);
}

// --- AMBIGUOUS: the claim must be RETAINED (no flag) ---

// 4. verify -> auth-layer failure (401): nothing proven either way.
{
  const r = await call(js({ error: 'invalid token' }, 401),
                       js({ error: 'should not be reached' }, 500));
  console.log('verify 401       ->', JSON.stringify({ ok: r.ok, dns: r.definitelyNotSubmitted, retryable: r.retryable }));
  ok('auth-layer failure does NOT claim certainty', r.definitelyNotSubmitted !== true, r);
}

// 5. settle -> 5xx: ambiguous, must stay unknown.
{
  const r = await call(js({ isValid: true }, 200), js({ error: 'upstream' }, 503));
  console.log('settle 503       ->', JSON.stringify({ ok: r.ok, unknown: r.settledUnknown, dns: r.definitelyNotSubmitted }));
  ok('settle 5xx stays settledUnknown', r.settledUnknown === true, r);
  ok('settle 5xx is not marked definitelyNotSubmitted', r.definitelyNotSubmitted !== true, r);
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R32-NONCE-FAIL (${fails.length})`
  : 'R32-NONCE-ALL-PASS (proven no-settlement paths set definitelyNotSubmitted -> ' +
    'DO claim released; ambiguous paths retain the claim)');
process.exit(fails.length ? 1 : 0);
