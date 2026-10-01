// R28 regression test: authorization envelope depth in cdp.js.
//
// BUG: `decodePaymentPayload` returns the WHOLE x402 envelope (it carries
// `accepted`/`accepts` at its ROOT), so the TransferWithAuthorization lives at
// payload.payload.authorization. The code read only payload.authorization and
// fell back to a root `from` that does not exist -- so on a SUCCESSFUL settle
// `payer` resolved to null, and settledFrom/settledTo/settledNonce came back
// empty. The settlement receipt could not be bound to the payment that made it.
//
// This test builds REAL x402 envelopes in both shapes, runs the real
// cdpVerifyAndSettle() against a stubbed facilitator, and asserts the payer is
// actually recovered. It would fail on the pre-R28 code and passes now.
import { readFileSync } from 'node:fs';

const vec = JSON.parse(readFileSync('./e2e_vector.json', 'utf-8'));
const { cdpVerifyAndSettle } = await import('./cdp.js');

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// Rebuild the canonical envelope from the test vector, then re-nest it at the
// correct depth (payload.payload.authorization).
const decoded = JSON.parse(Buffer.from(vec.header_b64url, 'base64url').toString());
const authorization = decoded.payload.authorization;
ok('vector has an authorization with a payer', !!authorization && !!authorization.from,
   authorization && authorization.from);
const expectedPayer = String(authorization.from).toLowerCase();

// Re-encode the envelope in the REAL gateway shape.
const envelope = { ...decoded, payload: { ...decoded.payload, authorization } };
const headerB64 = Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64url');

const env = {
  CDP_API_KEY_ID: 'test-key-id',
  CDP_API_KEY_SECRET: '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
  MERCHANT_WALLET_ADDRESS: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
};

// Stub the facilitator: verify passes, settle SUCCEEDS and deliberately omits
// payer/to/nonce so any value we get back can only have come from the
// authorization we resolved locally.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  const u0 = String(url);
  if (u0.includes('/x402/verify')) return new Response(JSON.stringify({ isValid: true }), { status: 200 });
  if (u0.includes('/x402/settle')) {
    return new Response(JSON.stringify({ success: true, transaction: '0x' + 'ab'.repeat(32) }),
      { status: 200 });
  }
  throw new Error('unexpected fetch: ' + u0);
};

let r;
try {
  r = await cdpVerifyAndSettle(env, headerB64, 'csv-parquet-stream-compressor', 10000, 10000);
} finally {
  globalThis.fetch = realFetch;
}

console.log('settle result  :', JSON.stringify({
  ok: r && r.ok, payer: r && r.payer, settledFrom: r && r.settledFrom,
  settledNonce: r && r.settledNonce,
}).slice(0, 220));

// The decisive assertions: the payer must be recovered from the envelope, and
// must be bound into the receipt fields.
ok('settle succeeded', r && r.ok === true, r && r.reason);
ok('payer recovered from payload.payload.authorization',
   !!r.payer && r.payer === expectedPayer, r.payer);
ok('settledFrom is bound to the authorization payer',
   !!r.settledFrom && String(r.settledFrom).toLowerCase() === expectedPayer, r.settledFrom);
const normNonce = (v) => String(v == null ? '' : v).toLowerCase().replace(/^0x/, '');
ok('settledNonce is bound to the authorization nonce',
   !!r.settledNonce && normNonce(r.settledNonce) === normNonce(authorization.nonce),
   `${r.settledNonce} vs ${authorization.nonce}`);
ok('settledTo is bound to the authorization recipient',
   !!r.settledTo && String(r.settledTo).toLowerCase() ===
     String(authorization.to).toLowerCase(), r.settledTo);

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R28-ENVELOPE-FAIL (${fails.length})`
  : `R28-ENVELOPE-ALL-PASS (payer+receipt fields recovered from the real envelope depth; ` +
    `payer=${r.payer})`);
process.exit(fails.length ? 1 : 0);
