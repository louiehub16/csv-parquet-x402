// Re-mint e2e_vector.json with FRESH time windows.
// Run this whenever the e2e happy-path vector ages out of its validBefore
// window ("happy path accepts genuine payment" starts failing with
// time_window_violation even though nothing changed):  node mint_vector.mjs
// Throwaway keys only — these authorize no real funds (value is micro-USDC
// test amounts against a test merchant address).
import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { G, N, hexToBigInt, bigIntToBytes32, bytesToBigInt, scalarMult } from './_secp256k1.js';
import { keccak256, twaDigest, pubkeyToAddress } from './x402.js';

// Merchant MUST be the address the gateway actually paysTo: wrangler.jsonc
// vars.MERCHANT_WALLET_ADDRESS and public/.well-known/x402.json both use
// 0x795dCA28.... A vector paying anyone else is rejected as wrong_recipient.
const MERCHANT = '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NONCE = '0x' + 'ab'.repeat(32);

// --- local ECDSA sign (modInv is private in _secp256k1.js) ---
function modInv(a, m) {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('not invertible');
  return ((oldS % m) + m) % m;
}

function sign(digestBytes, priv) {
  const z = bytesToBigInt(digestBytes);
  for (let attempt = 0; attempt < 64; attempt++) {
    // deterministic-ish nonce: keccak(digest || priv || attempt)
    const kSeed = keccak256(new Uint8Array([
      ...digestBytes, ...bigIntToBytes32(priv), ...bigIntToBytes32(BigInt(attempt)),
    ]));
    let k = bytesToBigInt(kSeed) % N;
    if (k === 0n) continue;
    const R = scalarMult(k, G);
    let r = R.x % N;
    if (r === 0n) continue;
    let s = (modInv(k, N) * (z + r * priv)) % N;
    if (s === 0n) continue;
    let recId = R.y & 1n ? 1 : 0;
    if (s > N / 2n) { s = N - s; recId ^= 1; } // low-s normalization
    return { r, s, recId };
  }
  throw new Error('signing failed');
}

const hex32 = (v) => '0x' + v.toString(16).padStart(64, '0');
function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeHeader(auth, priv) {
  const digest = twaDigest({ ...auth, nonce: auth.nonce });
  const { r, s, recId } = sign(digest, priv);
  // The v2 `accepted` requirements object is REQUIRED and validated field by
  // field (x402.js verifyPayment): scheme/network/amount/asset/payTo must match
  // exactly and maxTimeoutSeconds must equal the 600 we advertise. Omitting it
  // makes EVERY paid-path suite fail with malformed_requirements/missing_accepts.
  const accepted = {
    scheme: 'exact',
    network: 'eip155:8453',
    amount: String(auth.value),
    asset: USDC,
    payTo: auth.to,
    maxTimeoutSeconds: 600,
    extra: { name: 'USD Coin', version: '2' },
  };
  return {
    x402Version: 2,
    scheme: 'exact',
    network: 'eip155:8453',
    accepted,
    payload: {
      signature: { r: hex32(r), s: hex32(s), v: recId + 27 },
      authorization: auth
    },
  };
}

// --- mint ---
const now = Math.floor(Date.now() / 1000);
let d = 0n;
while (d === 0n) d = bytesToBigInt(randomBytes(32)) % N; // throwaway payer key
const Q = scalarMult(d, G);
const payerAddr = pubkeyToAddress(Q.x, Q.y);

// Window MUST stay inside the 600s bound verifyPayment enforces
// (`vb - va > 600` => time_window_violation). Keep a 555s span, matching the
// previously committed vector; validAfter is backdated so `now > va` holds.
const happyAuth = {
  from: payerAddr, to: MERCHANT, value: 10000,
  validAfter: now - 60, validBefore: now + 495, nonce: NONCE,
};
const wrongAmountAuth = { ...happyAuth, value: 1 };
// Legacy expired convention: validBefore < validAfter -> malformed_time_window
const expiredAuth = { ...happyAuth, validAfter: now + 600, validBefore: now + 540 };

const vec = {
  header_b64url: b64url(makeHeader(happyAuth, d)),
  expected_amount: '10000',
  payer_expected: payerAddr,
  merchant: MERCHANT,
  sig_v: 28,
  wrong_amount_header_b64url: b64url(makeHeader(wrongAmountAuth, d)),
  expired_header_b64url: b64url(makeHeader(expiredAuth, d)),
};
writeFileSync(new URL('./e2e_vector.json', import.meta.url), JSON.stringify(vec, null, 2) + '\n');
console.log('minted fresh e2e_vector.json | payer:', payerAddr,
  '| window:', happyAuth.validAfter, '->', happyAuth.validBefore);
