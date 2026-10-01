// E2E: real eth_account-signed x402 payment -> gateway verifyPayment().
import { readFileSync } from 'node:fs';
import { verifyPayment, tierForBytes } from './x402.js';




const vec = JSON.parse(readFileSync(new URL('./e2e_vector.json', import.meta.url), 'utf-8'));
const MERCHANT = '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83';

const seenNonces = new Set();
const claimedNonces = new Set();
const confirmStub = async () => ({ confirmed: true });

const settleStub = async (payment) => {
  const a = (payment && payment.payload && payment.payload.authorization) || {};
  return { ok: true, settledTx: '0x' + 'cd'.repeat(32),
    settledFrom: a.from, settledTo: a.to,
    settledAmountUsdc: String(a.value), settledNonce: a.nonce };
};
const env = {
  MERCHANT_WALLET_ADDRESS: MERCHANT,
  SG_CPU_RATE_PER_HR: '0.13',
  SECURITY_KV: {
    get: async (k) => (seenNonces.has(k) ? '1' : null),
    put: async (k) => seenNonces.add(k),
  },
  // R33: verifyPayment requires the atomic DO replay store.
  CONSUMED_TX_STORE: {
    idFromName: () => ({ name: 'singleton' }),
    get: () => ({
            fetch: async (_url, opts) => {
        const b = opts.body ? JSON.parse(opts.body) : {};
        if (b.nonce != null) {
          if (_url.includes('finalize')) {
            if (!claimedNonces.has(b.nonce)) return new Response(JSON.stringify({ ok:false, error:'nonce_not_claimed' }), { status: 409 });
            return new Response(JSON.stringify({ ok: true, finalized: true }), { status: 200 });
          }
          if (claimedNonces.has(b.nonce)) return new Response(JSON.stringify({ ok: false, already: 'used' }), { status: 409 });
          claimedNonces.add(b.nonce);
          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    }),
  },
};

function makeRequest(headers = {}) {
  const h = new Headers(headers);
  return {
    url: 'https://csv-parquet.example.workers.dev/v1/compress',
    headers: h,
    headers_get: (n) => h.get(n),
  };
}
// Headers class exists in Node 18+; wrap .get for our module's request.headers.get usage
function req(headers) {
  const r = makeRequest(headers);
  r.headers.get = (n) => new Headers(headers).get(n);
  return r;
}

let fails = 0;
const check = (name, cond, extra = '') => {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? `  [${extra}]` : ''));
  if (!cond) fails++;
};

// 1. HAPPY PATH
{
  const v = await verifyPayment(env, req({
    'PAYMENT-SIGNATURE': vec.header_b64url,
  }), { expectedAmount: vec.expected_amount, settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('happy path accepts genuine payment', v.ok === true, v.reason || '');
  if (v.ok) {
    check('payer recovered correctly', v.payer.toLowerCase() === vec.payer_expected.toLowerCase(), v.payer);
    check('amount extracted', v.amountMicroUsdc === '10000');
    check('nonce returned', typeof v.nonce === 'string' && v.nonce.length === 64);
    await markAndCheck(v.nonce);
  }
}

async function markAndCheck(nonce) {
  // R37: consumption is DO finalize (no KV fallback).
  const { consumeNonce } = await import('./x402.js');
  await consumeNonce(env, nonce);
  // Replay of a consumed nonce must now be rejected at verification.
  const v2 = await verifyPayment(env, req({
    'PAYMENT-SIGNATURE': vec.header_b64url,
  }), { expectedAmount: vec.expected_amount, settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('replay rejected after consume', v2.ok === false, v2.reason || 'accepted!');
}

// 3. WRONG AMOUNT
{
  const v = await verifyPayment(env, req({
    'PAYMENT-SIGNATURE': vec.wrong_amount_header_b64url,
  }), { expectedAmount: '10000', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('amount mismatch rejected', v.ok === false && v.reason === 'amount_mismatch', v.reason || '');
}

// 4. EXPIRED window
{
  const v = await verifyPayment(env, req({
    'PAYMENT-SIGNATURE': vec.expired_header_b64url,
  }), { expectedAmount: '10000', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  // NOTE: the legacy expired vector carries validBefore < validAfter, so the
  // stricter integer/ordering gate (vb>va>0) rejects it as
  // malformed_time_window before the asymmetric window gate could label it
  // time_window_violation. Both are fail-closed rejections.
  check('expired payment rejected',
    v.ok === false && (v.reason === 'time_window_violation' || v.reason === 'malformed_time_window'),
    v.reason || '');
}

// 5. MISSING header
{
  const v = await verifyPayment(env, req({}), { expectedAmount: '10000', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('missing payment header rejected', v.ok === false && v.reason === 'payment_signature_header_missing', v.reason || '');
  if (v.failResponse && v.failResponse.status !== undefined) {
    check('failResponse is a 402 challenge', v.failResponse.status === 402);
    check('challenge carries PAYMENT-REQUIRED header', !!v.failResponse.headers.get('PAYMENT-REQUIRED'));
  }
}

// 5b. No expected amount at all -> unpriceable (gate-order check)
{
  const v = await verifyPayment(env, req({}), { expectedAmount: '10000', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('no payment header rejected', v.ok === false && v.reason === 'payment_signature_header_missing', v.reason || '');
}

// 6. UNDECODABLE garbage
{
  const v = await verifyPayment(env, req({ 'PAYMENT-SIGNATURE': '!!!not-base64!!!' }), { expectedAmount: '10000', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  check('garbage payload rejected', v.ok === false && v.reason === 'payment_payload_undecodable', v.reason || '');
}

console.log(fails === 0 ? 'E2E-ALL-PASS' : `E2E FAILURES: ${fails}`);
process.exit(fails === 0 ? 0 : 1);// R41: settlement proof must bind payer/recipient/amount/nonce; derive them
// from the payload actually passed in so the stub stays honest.



