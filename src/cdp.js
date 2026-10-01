// cdp.js — Coinbase Developer Platform x402 facilitator adapter (dependency-free).
//
// Ported from the dual-reviewed docker-on-tap adapter (12+ review rounds, converged)
// and adapted to this project's zero-dependency curve code: @noble/curves and
// @noble/hashes are replaced by our own _secp256k1.js (secp256k1 + keccak256 +
// sha256 + ECDSA signing).
//
// WHY: settlement is the primary payment rail that seeds Coinbase CDP Bazaar and
// x402scan auto-indexing. Without it, verified-but-unsettled authorizations are
// uncollectible. This adapter makes settlement a first-class step of the paid path.
//
// Endpoints:
//   POST https://api.cdp.coinbase.com/platform/v2/x402/verify
//   POST https://api.cdp.coinbase.com/platform/v2/x402/settle
//
// Auth: ES256K JWT signed with the CDP API key (key id = kid, key secret = PEM/hex/base64).
//
// Result contract (never throws — every failure is a discriminated result):
//   { mode:'cdp', ok:true,  settledTx, amountMicroUsdc, payer }
//   { mode:'cdp', ok:false, retryable:true }              // CDP down/ambiguous -> caller may fall back
//   { mode:'cdp', ok:false, retryable:false, reason }     // genuine payment rejection -> no fallback
//
// minMicroUsdc     : floor (cheap sanity bound)
// expectedAmountUsdc: the EXACT price the server computed from the request byte size;
//                    when provided, the client's declared amount must equal it exactly.

import { sha256, signDigest } from './_secp256k1.js';
import { keccak256 } from './x402.js';

const CDP_BASE = 'https://api.cdp.coinbase.com/platform/v2/x402';
// CDP's API-key JWT expects the `uri` claim to include the HOST, e.g.
// "POST api.cdp.coinbase.com/platform/v2/x402/verify". Building it with only the
// path makes the facilitator 401 every call (CDP rail dead, silent fallback forever).
const CDP_HOST = 'api.cdp.coinbase.com';
const JWT_LIFETIME_S = 120;

export function cdpConfigured(env) {
  return !!(env && env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET);
}

// ------------------------------------------------------------------ helpers
const utf8 = (s) => new TextEncoder().encode(String(s));
const b64u = (bytes) => {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64uToBytes = (s) => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function validateScalar(bytes) {
  if (!bytes || bytes.length !== 32) return null;
  if (bytes.every((b) => b === 0)) return null;
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  if (acc >= SECP256K1_N) return null; // must be 0 < s < n
  return bytes;
}

// Accepts the private key in ANY of: hex (with/without 0x), raw base64
// (padded or unpadded, RFC-4648, possibly base64url charset), or PEM (PKCS#8 / SEC1).
// The CDP portal exports base64 by default, so that path must work.
function normalizePrivateKey(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  let s = raw.trim();

  // 1) PEM (never ENCRYPTED — its body is ciphertext).
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) {
    if (/ENCRYPTED PRIVATE KEY/.test(s)) return null;
    const body = s.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/, '')
      .replace(/-----END [A-Z ]*PRIVATE KEY-----/, '')
      .replace(/\s+/g, '');
    return derToPrivKey(b64uToBytes(body));
  }

  // 2) Base64 / base64url. Strip any 0x first so a hex key is never routed here.
  {
    const stripped = s.replace(/^0x/i, '');
    const norm = stripped.replace(/-/g, '+').replace(/_/g, '/');
    const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4);
    const b64re = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    if (b64re.test(padded) && !/^[0-9a-fA-F]+$/.test(stripped)) {
      try {
        const bytes = b64uToBytes(padded);
        if (bytes.length === 32) return validateScalar(bytes);
        return derToPrivKey(bytes);
      } catch (e) { return null; }
    }
  }

  // 3) Hex.
  const clean = s.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) return null;
  const hexBytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < hexBytes.length; i++) hexBytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  if (hexBytes.length === 32) return validateScalar(hexBytes);
  return derToPrivKey(hexBytes);
}

// Best-effort DER walker for SEC1/PKCS#8 keys. Collects every 32-byte OCTET
// STRING and lets validateScalar pick the real scalar, so a crafted unrelated
// byte run cannot be accepted blindly.
function derToPrivKey(der) {
  try {
    if (!der || der.length < 8 || der[0] !== 0x30) return null;
    const cands = [];
    collectOctetStrings(der, 0, der.length, cands);
    for (const c of cands) {
      const v = validateScalar(c);
      if (v) return v;
    }
    return null;
  } catch (e) { return null; }
}

function collectOctetStrings(der, start, end, out) {
  let i = start;
  while (i + 2 <= end) {
    const tag = der[i++];
    let len = der[i++];
    if (len > 127) {
      const n = len & 0x7f;
      if (n === 0 || n > 4 || i + n > end) return;
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
    }
    const cs = i, ce = cs + len;
    if (ce > end) return;
    i = ce;
    const content = der.slice(cs, ce);
    if (tag === 0x04) {
      if (content.length === 32) out.push(content);
      else if (content.length > 32) collectOctetStrings(der, cs, ce, out);
    } else if (tag === 0x30 || tag === 0x31) {
      collectOctetStrings(der, cs, ce, out);
    }
  }
}

// ---------------------------------------------------------------- JWT build
async function buildCdpJwt(env, requestMethod, requestPath) {
  const priv = normalizePrivateKey(env.CDP_API_KEY_SECRET);
  if (!priv) return null;
  const now = Math.floor(Date.now() / 1000);
  const headerB64u = b64u(utf8(JSON.stringify({
    alg: 'ES256K', kid: env.CDP_API_KEY_ID, typ: 'JWT',
  })));
  const payloadB64u = b64u(utf8(JSON.stringify({
    sub: env.CDP_API_KEY_ID,
    iss: 'cdp',
    nbf: now,
    exp: now + JWT_LIFETIME_S,
    uri: `${requestMethod.toUpperCase()} ${CDP_HOST}${requestPath}`,
  })));
  const signingInput = `${headerB64u}.${payloadB64u}`;
  const digest = await sha256(utf8(signingInput));
  let sig;
  try {
    sig = await signDigest(digest, priv);
  } catch (e) {
    return null;
  }
  // JWS ES256K is FIXED-WIDTH 64-byte r||s — NOT ASN.1 DER (CDP rejects DER).
  const jose = new Uint8Array(64);
  const rv = sig.r.toString(16).padStart(64, '0');
  const sv = sig.s.toString(16).padStart(64, '0');
  for (let i = 0; i < 32; i++) jose[i] = parseInt(rv.substr(i * 2, 2), 16);
  for (let i = 0; i < 32; i++) jose[32 + i] = parseInt(sv.substr(i * 2, 2), 16);
  return `${signingInput}.${b64u(jose)}`;
}

// ------------------------------------------------------------ classification
// A facilitator HTTP response is a DEFINITIVE permanent payment rejection only
// when it carries a concrete payment verdict. Auth-layer failures at 400/422 are
// TRANSIENT (our 120s JWT vs the facilitator's clock, key rotation) and must stay
// retryable so the on-chain fallback remains available.
function reasonString(errBody) {
  if (!errBody) return '';
  const any = errBody.error || errBody.reason || errBody.invalidReason || errBody.message || errBody;
  return typeof any === 'string' ? any : JSON.stringify(any);
}

function isPermanentRejection(status, errBody) {
  if (status === 402) return true; // explicit payment verdict
  if (status === 409) {
    // R27: a 409 is NOT proof that nothing settled. "already settled" means the
    // transfer very likely DID move (this is a retry of a payment that already
    // completed), so classifying it as definitely-not-submitted released the
    // nonce and scheduled no refund -- the payer paid and got nothing.
    // Only a 409 that names a genuinely unusable authorization (a different
    // payer/amount/recipient conflict) is a clean "nothing moved" answer.
    const r = reasonString(errBody);
    if (/already.{0,40}(?:settled|used|consumed|complete)/i.test(r) &&
        !/conflict|does not match|different|mismatch/i.test(r)) {
      return false;   // ambiguous: treat as settled-unknown -> refund path
    }
    return true;
  }
  if (status === 400 || status === 422) {
    const r = reasonString(errBody);
    // (a) Auth-layer failures are NEVER permanent.
    if (/jwt|token|bearer|credential|api[ -]?key|authentication|unauthori[sz]ed/i.test(r)) return false;
    // (b) Only a body naming a PAYMENT-phase failure is permanent.
    return /invalid.{0,40}(?:amount|payment|nonce|payload|signature)|already.{0,40}(?:used|settled|consumed)|(?:payment|authorization|nonce|payload).{0,40}expired|expired.{0,40}(?:payment|authorization|nonce|payload)|insufficient|malformed.{0,40}(?:amount|payload)|nonce.{0,40}(?:used|invalid)/i.test(r);
  }
  return false; // 401/403/404/408/425/429/5xx -> retryable
}

function isRejectionReason(reason) {
  return /^(?:invalid|expired|already|nonce|insufficient|signature|malformed|amount|payload|payment|rejected)/i.test(reason || '');
}

function decodePaymentPayload(b64) {
  if (typeof b64 !== 'string' || !b64.length) return null;
  try {
    const obj = JSON.parse(new TextDecoder().decode(b64uToBytes(b64)));
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
  } catch (e) { return null; }
}

// Facilitator error text can echo back payment payloads or credential fragments.
// Never propagate it: only codes WE define are ever returned.
const ALLOWED_REASONS = new Set([
  'malformed_payment_payload', 'missing_accepts', 'malformed_amount', 'underpayment',
  'amount_mismatch', 'verify_failed', 'settle_failed', 'settle_unconfirmed',
  'settle_tx_unproven', 'expected_amount_missing', 'expected_amount_config_invalid',
  'min_amount_config_invalid',
]);
function safeReason(body, fallback) {
  const r = reasonString(body);
  // Only pass through a code that is in our own vocabulary; anything else
  // (including a short facilitator string that happens to look like a token)
  // collapses to the caller's internal fallback.
  if (r && ALLOWED_REASONS.has(r)) return r;
  return fallback;
}

// ------------------------------------------------------------- MAIN ENTRY
export async function cdpVerifyAndSettle(env, paymentHeaderB64, resourceName, minMicroUsdc, expectedAmountUsdc) {
  if (!cdpConfigured(env)) return { mode: 'cdp', ok: false, retryable: true };

  const payload = decodePaymentPayload(paymentHeaderB64);
  if (!payload) return { mode: 'cdp', ok: false, retryable: false, reason: 'malformed_payment_payload' };

  // R28: resolve the authorization ONCE, from the correct envelope depth.
  // `payload` is the whole decoded x402 envelope (it carries `accepted` /
  // `accepts` at its ROOT), so the TransferWithAuthorization lives at
  // payload.payload.authorization. The previous code read only
  // payload.authorization, missed the real location, and fell through to a root
  // fallback that does not exist -- so payer/settledFrom/settledNonce all came
  // back null on SUCCESSFUL payments.
  const authEnvelope = (payload && payload.payload && payload.payload.authorization
    && typeof payload.payload.authorization === 'object')
    ? payload.payload.authorization
    : ((payload && payload.authorization && typeof payload.authorization === 'object')
      ? payload.authorization
      : null);

  // Requirements may arrive as a singular `accepted` object (v2 standard) or an
  // `accepts` array (early SDK shape). Read whichever is present.
  const reqObj = (payload.accepted && typeof payload.accepted === 'object' && !Array.isArray(payload.accepted))
    ? payload.accepted
    : (Array.isArray(payload.accepts) && payload.accepts.length ? payload.accepts[0] : null);
  if (!reqObj) return { mode: 'cdp', ok: false, retryable: false, reason: 'missing_accepts' };

  // Validate the amount BEFORE any facilitator call — malformed payment data must
  // never settle and only be discovered afterwards.
  const rawAmount = reqObj.amount != null ? String(reqObj.amount) : '0';
  if (!/^(?:0|[1-9][0-9]*)$/.test(rawAmount)) {
    return { mode: 'cdp', ok: false, retryable: false, reason: 'malformed_amount' };
  }
  // R15 SECURITY: the client-declared amount is checked against the floor ONLY,
  // which let a client underpay (e.g. declare 1 against a 10000 tier price).
  // When the server passes expectedAmountUsdc (the exact price it computed from
  // the request's byte size), require EXACT equality here. A mismatch is a
  // genuine payment rejection — never fall back to the offline path, which
  // would apply the same lenient floor.
  // R16: the exact server price is MANDATORY — settling against the floor
  // alone is what allowed a client to declare a tiny amount and still pass.
  // A missing/invalid expectedAmount is a server misconfiguration: fail
  // closed and retryable (never settle with the weaker check).
  if (expectedAmountUsdc == null) {
    console.error('[cdp] expectedAmountUsdc missing — refusing to settle on floor only');
    return { mode: 'cdp', ok: false, retryable: true, reason: 'expected_amount_missing' };
  }
  let expected = null;
  try {
    expected = BigInt(String(expectedAmountUsdc));
  } catch (e) {
    console.error('[cdp] invalid expectedAmountUsdc config:', String(expectedAmountUsdc));
    return { mode: 'cdp', ok: false, retryable: true, reason: 'expected_amount_config_invalid' };
  }
  if (expected < 0n) {
    return { mode: 'cdp', ok: false, retryable: true, reason: 'expected_amount_config_invalid' };
  }
  if (BigInt(rawAmount) !== expected) {
    return { mode: 'cdp', ok: false, retryable: false, reason: 'amount_mismatch' };
  }
  // Enforce the minimum HERE: otherwise a client-supplied amount of 1 would
  // settle and return ok:true, and the caller would skip the legacy verifier.
  // Guard the conversion: minMicroUsdc is server config, but a malformed value
  // must degrade to a retryable result, never throw out of this function.
  let required = 0n;
  if (minMicroUsdc != null) {
    try {
      required = BigInt(String(minMicroUsdc));
    } catch (e) {
      console.error('[cdp] invalid minMicroUsdc config:', String(minMicroUsdc));
      return { mode: 'cdp', ok: false, retryable: true, reason: 'min_amount_config_invalid' };
    }
    if (required < 0n) return { mode: 'cdp', ok: false, retryable: true, reason: 'min_amount_config_invalid' };
  }
  if (required > 0n && BigInt(rawAmount) < required) {
    return { mode: 'cdp', ok: false, retryable: false, reason: 'underpayment' };
  }

  try {
    // ---- STEP 1: VERIFY ----
    const jwtV = await buildCdpJwt(env, 'POST', '/platform/v2/x402/verify');
    if (!jwtV) return { mode: 'cdp', ok: false, retryable: true };
    const verifyRes = await fetch(`${CDP_BASE}/verify`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${jwtV}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        x402Version: 2,
        paymentHeader: paymentHeaderB64,
        resource: resourceName || 'csv-parquet-stream-compressor',
      }),
    });
    if (!verifyRes.ok) {
      const errBody = await verifyRes.json().catch(() => ({}));
      const perm = isPermanentRejection(verifyRes.status, errBody);
      return {
        mode: 'cdp', ok: false, retryable: !perm,
        reason: safeReason(errBody, `verify_http_${verifyRes.status}`),
      };
    }
    const vData = await verifyRes.json();
    if (!vData || vData.isValid !== true) {
      const reason = safeReason(vData, 'verify_failed');
      return { mode: 'cdp', ok: false, retryable: !isRejectionReason(reason), reason };
    }

    // ---- STEP 2: SETTLE ----
    const jwtS = await buildCdpJwt(env, 'POST', '/platform/v2/x402/settle');
    if (!jwtS) return { mode: 'cdp', ok: false, retryable: true };
    const settleRes = await fetch(`${CDP_BASE}/settle`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${jwtS}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        x402Version: 2,
        paymentHeader: paymentHeaderB64,
        resource: resourceName || 'csv-parquet-stream-compressor',
      }),
    });
    if (!settleRes.ok) {
      const sErr = await settleRes.json().catch(() => ({}));
      // R16: once /settle has been SUBMITTED, any non-definitive status
      // (408/425/429/5xx, and a 4xx whose body doesn't name a payment fault)
      // is AMBIGUOUS: the transfer may or may not have executed. Only a
      // provable payment verdict (400/402/409 naming the payment) is a clean
      // "not paid" answer. Everything else is settled-unknown so the caller
      // cannot fall back and re-serve the same authorization.
      if (isPermanentRejection(settleRes.status, sErr)) {
        return {
          // Facilitator gave a definitive payment verdict, so nothing settled.
          definitelyNotSubmitted: true,
          mode: 'cdp', ok: false, retryable: false,
          reason: safeReason(sErr, `settle_http_${settleRes.status}`),
        };
      }
      console.error('[cdp] settle ambiguous status', settleRes.status);
      return {
        mode: 'cdp', ok: false, retryable: false, settledUnknown: true,
        reason: safeReason(sErr, `settle_ambiguous_${settleRes.status}`),
      };
    }
    const sData = await settleRes.json();
    if (!sData || sData.success !== true) {
      // 2xx without success: only an explicit payment-phase reason is a clean
      // rejection; anything else is an ambiguous post-submission state.
      const reason = safeReason(sData, 'settle_failed');
      if (isRejectionReason(reason)) {
        return { mode: 'cdp', ok: false, retryable: false, reason };
      }
      return { mode: 'cdp', ok: false, retryable: false, settledUnknown: true, reason: 'settle_unconfirmed' };
    }

    // R28: read the payer from the resolved authorization (both envelope depths
    // handled above), falling back to a root `from` for exotic shapes.
    const payer = (authEnvelope && authEnvelope.from)
      ? String(authEnvelope.from).toLowerCase()
      : (payload.from && typeof payload.from === 'string'
        ? payload.from.toLowerCase() : null);

    // R17: a success flag WITHOUT a transaction identifier is unprovable
    // settlement. Require a real tx hash — the caller records it as the
    // payment's durable proof, and an unprovable settle must not unlock work.
    const settledTx = sData.transaction || sData.txHash ||
      (sData.settlement && sData.settlement.txHash) || null;
    if (typeof settledTx !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(settledTx)) {
      console.error('[cdp] settle reported success without a transaction hash');
      return { mode: 'cdp', ok: false, retryable: false, settledUnknown: true, reason: 'settle_tx_unproven' };
    }
    return {
      mode: 'cdp',
      ok: true,
      settledTx,
      amountMicroUsdc: rawAmount, // canonical integer string — safe for BigInt()
      payer,
      // R41: echo the settled identity so the caller can bind the receipt to
      // the authorization it verified (payer/recipient/amount/nonce).
      // Prefer what the facilitator actually reported settled; fall back to the
      // authorization when the response omits it.
      settledFrom: (sData.payer || sData.from || payer) || null,
      settledTo: sData.payTo || sData.to || (authEnvelope && authEnvelope.to) || reqObj.payTo || null,
      settledAmountUsdc: (sData.amount != null ? String(sData.amount) : rawAmount) || null,
      settledNonce: sData.nonce || (authEnvelope && authEnvelope.nonce) || null,
      // We DID submit to the facilitator, so this is never 'definitely not submitted'.
      definitelyNotSubmitted: false,
    };
  } catch (e) {
    // Ambiguous settlement state (transport error / unparsed body). The
    // authorization MAY or MAY NOT have settled on-chain, so we must NOT let the
    // caller treat this as a clean "not paid" and re-serve the same
    // authorization. Report it as UNSETTLED: the gateway must stop and require a
    // fresh payment, rather than falling back to the offline path.
    console.error('[cdp] settlement outcome ambiguous:', (e && e.message) || e);
    return { mode: 'cdp', ok: false, retryable: false, reason: 'settlement_ambiguous', settledUnknown: true };
  }
}
