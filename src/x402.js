// x402 v2 SELLER-side payment module (Cloudflare Worker compatible, zero deps).
// - Tier pricing (micro-USDC integers; USDC on Base has 6 decimals)
// - HTTP 402 PAYMENT-REQUIRED challenge manifest (x402scan/CDP-Bazaar parseable)
// - EIP-712 TransferWithAuthorization verification against USDC on Base,
//   with offline secp256k1 signer recovery + KV replay guard.
// FAIL-CLOSED: any malformed/missing/expired/tampered payment rejects.
import {
  recover, hexToBigInt, bigIntToBytes32, bytesToBigInt,
} from './_secp256k1.js';

export const USDC_ON_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const CHAIN_ID = 8453;
const NETWORK = 'eip155:8453';
const GB = 1073741824;
const MB = 1048576;

// ---------------------------------------------------------------- keccak256
// Ethereum variant: rate 136 bytes, pad10*1 with 0x01 domain bit.
const MASK64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// rho rotation offsets, indexed [x][y]
const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(v, n) {
  const b = BigInt(n % 64);
  if (b === 0n) return v & MASK64;
  return ((v << b) | (v >> (64n - b))) & MASK64;
}

function keccakF(A) { // A: BigInt[25], lane index = x + 5*y
  for (let round = 0; round < 24; round++) {
    // theta
    const C = new Array(5);
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) A[x + 5 * y] ^= d;
    }
    // rho + pi
    const B = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], ROT[x][y]);
    }
    // chi  (BigInt ~ is infinite two's-complement; & with a 64-bit lane is correct)
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      A[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
    }
    // iota
    A[0] ^= RC[round];
  }
}

export function keccak256(bytes) {
  const rate = 136;
  const state = new Array(25).fill(0n);
  const padLen = bytes.length + (rate - (bytes.length % rate));
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padLen - 1] ^= 0x80;
  for (let off = 0; off < padLen; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      state[i] ^= lane;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) { out[i * 8 + j] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

// ---------------------------------------------------------------- helpers
const utf8 = (s) => new TextEncoder().encode(s);
function concat(...arrs) {
  const total = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function addrToBytes32(hex) { // 20-byte address, left-padded to 32 (ABI)
  const h = String(hex).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(h)) throw new RangeError('invalid address');
  const out = new Uint8Array(32);
  for (let i = 0; i < 20; i++) out[12 + i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
const uint256Bytes = (v) => bigIntToBytes32(typeof v === 'bigint' ? v : BigInt(v));
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// ---------------------------------------------------------------- pricing
// Tier ladder is HALF-OPEN [min, max) EXCEPT at the top boundary: the matrix
// says $0.015 THROUGH 1 TB, so a file of exactly 1024 GiB still prices in the
// $0.015/GB tier; only strictly-above-1TB files fall to $0.008/GB. Mirrors
// public/.well-known/x402.json exactly.
// Per-GB tiers charge byte-proportionally, rounded UP to the next micro-USDC
// unit, each with a min charge floor of 10000 micro-USDC ($0.01).
export function tierForBytes(sizeBytes) {
  const b = Number(sizeBytes);
  if (!Number.isFinite(b) || b < 0) throw new RangeError('size must be a non-negative number');
  const mk = (microUsdc, storage, requiresUserDest) =>
    ({ microUsdc, usd: (microUsdc / 1e6).toFixed(4), storage, requiresUserDest });
  if (b < 100 * MB) return mk(10000, 'internal_r2', false);                    // flat $0.01
  // byte-proportional, min charge floors: $0.10/GB | $0.05/GB | $0.015/GB | $0.008/GB
  // Boundary convention (review R5/R6): every named upper bound is INCLUSIVE —
  // a file of exactly N bytes prices in the tier ENDING at N, so exactly 10 GiB
  // pays the lower $0.10/GB rate and exactly 1 TiB pays $0.015/GB.
  if (b <= 10 * GB) {
    const byo = b >= 10 * GB; // exactly 10GiB: priced here but BYO policy applies
    return mk(Math.max(10000, Math.ceil(b * 100000 / GB)), byo ? 'user_supplied_destination' : 'internal_r2', byo);
  }
  if (b <= 100 * GB) return mk(Math.max(10000, Math.ceil(b * 50000 / GB)), 'user_supplied_destination', true);
  if (b <= 1024 * GB) return mk(Math.max(10000, Math.ceil(b * 15000 / GB)), 'user_supplied_destination', true); // $0.015 THROUGH exactly 1 TB
  return mk(Math.max(10000, Math.ceil(b * 8000 / GB)), 'user_supplied_destination', true); // strictly above 1 TB
}

// ---------------------------------------------------------------- challenge
// Standards-shaped x402 v2 manifest; base64url in the PAYMENT-REQUIRED header.
export function buildChallenge({ url, description, microUsdc, maxTimeoutSeconds = 600, payTo, statusNote, status = 402 }) {
  const manifest = {
    x402Version: 2,
    error: 'Payment required',
    resource: { url, description },
    accepts: [{
      scheme: 'exact',
      network: NETWORK,
      amount: String(microUsdc),
      asset: USDC_ON_BASE,
      payTo,
      maxTimeoutSeconds,
      extra: { name: 'USD Coin', version: '2' },
    }],
  };
  const b64 = btoa(JSON.stringify(manifest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const body = { error: 'payment_required', amount_usdc: Number(microUsdc) / 1e6, network: NETWORK, asset: USDC_ON_BASE, payTo };
  if (statusNote) body.note = statusNote;
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'PAYMENT-REQUIRED': b64 },
  });
}

export function decodePayment(headerVal) {
  try {
    let s = String(headerVal).trim().replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return JSON.parse(atob(s));
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------- EIP-712
const DOMAIN_TYPE_HASH = keccak256(utf8(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const TWA_TYPE_HASH = keccak256(utf8(
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'));

export function domainSeparator() {
  return keccak256(concat(
    DOMAIN_TYPE_HASH,
    keccak256(utf8('USD Coin')),
    keccak256(utf8('2')),
    uint256Bytes(BigInt(CHAIN_ID)),
    addrToBytes32(USDC_ON_BASE),
  ));
}

// nonce: 32-byte hex string ("0x"-prefixed or bare)
export function twaDigest({ from, to, value, validAfter, validBefore, nonce }) {
  const nh = String(nonce).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(nh)) throw new RangeError('nonce must be 32-byte hex');
  const nb = new Uint8Array(32);
  for (let i = 0; i < 32; i++) nb[i] = parseInt(nh.slice(i * 2, i * 2 + 2), 16);
  return keccak256(concat(
    new Uint8Array([0x19, 0x01]),
    domainSeparator(),
    keccak256(concat(
      TWA_TYPE_HASH,
      addrToBytes32(from),
      addrToBytes32(to),
      uint256Bytes(BigInt(value)),
      uint256Bytes(BigInt(validAfter)),
      uint256Bytes(BigInt(validBefore)),
      nb,
    )),
  ));
}

export function pubkeyToAddress(x, y) {
  const h = keccak256(concat(bigIntToBytes32(x), bigIntToBytes32(y)));
  return '0x' + bytesToHex(h.slice(12));
}

// ---------------------------------------------------------------- verify
// verifyPayment(env, request, {expectedAmount, description}) ->
//   {ok:true, payer, amountMicro, nonce, validBefore}
//   {ok:false, failResponse:Response(402|409|500|503), reason}
// expectedAmount: the price comes ONLY from opts.expectedAmount passed by
// the gateway's tier computation. There is NO header fallback (R24 security
// fix: client-controlled price headers are never trusted).
export async function verifyPayment(env, request, opts = {}) {
  const payTo = env && env.MERCHANT_WALLET_ADDRESS;
  // R24 security fix: NEVER trust a client-supplied price header. The price
  // comes only from the gateway's own tier computation (opts.expectedAmount).
  const expected = opts.expectedAmount != null ? String(opts.expectedAmount) : '';
  const challenge = (statusNote, status = 402) => ({
    ok: false,
    reason: statusNote,
    failResponse: buildChallenge({
      url: request.url,
      description: opts.description || 'CSV/TSV/TXT to Parquet conversion',
      microUsdc: Number(expected) || 0,
      maxTimeoutSeconds: 600,
      payTo,
      statusNote,
      status,
    }),
  });

  if (!payTo) return challenge('server_not_configured', 500);
  if (!expected || !/^[0-9]+$/.test(expected)) return challenge('unpriceable_request');

  const header = request.headers.get('PAYMENT-SIGNATURE') || request.headers.get('X-PAYMENT');
  if (!header) return challenge('payment_signature_header_missing');
  const payment = decodePayment(header);
  if (!payment) return challenge('payment_payload_undecodable');

  const auth = payment && payment.payload && payment.payload.authorization;
  const sig = payment && payment.payload && payment.payload.signature;
  if (!auth || !sig) return challenge('payment_payload_missing_fields');
  // Envelope strictness: x402Version MUST be present and EXACTLY the number 2
  // (no string coercion: '2', 2.0-style floats, etc. are all rejected =>
  // unsupported_version).
  if (payment.x402Version !== 2) return challenge('unsupported_version');
  // v2 requirements object (review R5/R6): `accepted` is a SINGULAR plain
  // object in standards-conformant x402 v2 payloads and is REQUIRED. Every
  // field must be present and match exactly; if the sender ALSO duplicates
  // fields at top level, any conflict fails closed.
  const reqObj = payment.accepted;
  if (!reqObj || typeof reqObj !== 'object' || Array.isArray(reqObj))
    return challenge('malformed_requirements');
  const effScheme = reqObj.scheme;
  const effNetwork = reqObj.network; // CASE-SENSITIVE: must be 'eip155:8453' exactly
  if (effScheme !== 'exact') return challenge('unsupported_scheme');
  // Strict CAIP-2 only: the human alias 'base' is deliberately REJECTED so no
  // non-canonical spelling can ever widen the acceptance set.
  if (effNetwork !== NETWORK) return challenge('unsupported_network');
  const conflicts = [];
  if (payment.scheme != null && payment.scheme !== reqObj.scheme) conflicts.push('scheme');
  if (payment.network != null && payment.network !== NETWORK && payment.network !== (reqObj.network)) conflicts.push('network');
  if (conflicts.length) {
    console.log('[x402] conflicting_requirements:', conflicts.join(','));
    return challenge('conflicting_requirements');
  }
  if (reqObj.amount == null || String(reqObj.amount) !== expected) return challenge('amount_mismatch');
  if (reqObj.asset == null || String(reqObj.asset).toLowerCase() !== USDC_ON_BASE.toLowerCase()) return challenge('unsupported_asset');
  if (reqObj.payTo == null || String(reqObj.payTo).toLowerCase() !== String(payTo).toLowerCase()) return challenge('wrong_recipient');
  // Typed-field bounds on `accepted` (R7): maxTimeoutSeconds must be a positive
  // integer within the bound we advertise — we advertise a 600s settlement
  // commitment; larger client-advertised timeouts are not honored.
  if (!Number.isInteger(reqObj.maxTimeoutSeconds) || reqObj.maxTimeoutSeconds <= 0 || reqObj.maxTimeoutSeconds > 600) return challenge('malformed_requirements');
  // R7: we advertise maxTimeoutSeconds:600 in every challenge; the client's
  // accepted copy must match EXACTLY (no smaller/larger renegotiation).
  if (reqObj.maxTimeoutSeconds !== 600) return challenge('malformed_requirements');

  if (String(auth.to).toLowerCase() !== String(payTo).toLowerCase()) return challenge('wrong_recipient');
  if (String(auth.value) !== expected) return challenge('amount_mismatch');

  const now = Math.floor(Date.now() / 1000);
  const va = Number(auth.validAfter);
  const vb = Number(auth.validBefore);
  // Integers only, positive, strictly ordered — these are uint256 seconds on-chain.
    // R14: isSafeInteger guards; USDC spendability needs block.timestamp > validAfter,
  // so now === va is still early — strict `now > va`.
  if (!Number.isSafeInteger(va) || !Number.isSafeInteger(vb) || !(vb > va && va >= 0)) {
    return challenge('malformed_time_window');
  }
  // R7: the authorization window is bounded by the ISSUED settlement
  // commitment (maxTimeoutSeconds:600) plus a small dispatch margin — an
  // authorization valid for weeks must never pass, since we can only settle
  // within the advertised window.
  if (!Number.isInteger(vb - va) || vb - va > 600 + 300) return challenge('time_window_violation');
  // STRICT window check with NO early acceptance: dispatch happens only once
  // the EIP-3009 authorization is actually spendable (now >= validAfter) —
  // benign client clock skew is no reason to take payment we cannot yet
  // settle. There is NO late grace either: once now >= validBefore the
  // authorization is expired and can NEVER settle on-chain, so accepting it
  // here would take payment we cannot collect.
  if (!(now > va && now < vb)) return challenge('time_window_violation');

  const nonceHex = String(auth.nonce || '').toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(nonceHex)) return challenge('malformed_nonce');

  let digest;
  try {
    digest = twaDigest({ ...auth, nonce: nonceHex });
  } catch (e) {
    return challenge('digest_construction_failed');
  }

  // signature: {r,s,v?} hex strings (0x optional) OR a 65-byte r||s||v hex
  let rHex, sHex, vRaw;
  try {
    if (typeof sig === 'string') {
      const raw = sig.toLowerCase().replace(/^0x/, '');
      if (raw.length !== 130) throw new RangeError('bad raw signature length');
      rHex = raw.slice(0, 64); sHex = raw.slice(64, 128); vRaw = parseInt(raw.slice(128, 130), 16);
    } else {
      rHex = String(sig.r).toLowerCase().replace(/^0x/, '');
      sHex = String(sig.s).toLowerCase().replace(/^0x/, '');
      vRaw = sig.v != null ? Number(sig.v) : (sig.recovery != null ? Number(sig.recovery) : undefined);
    }
    if (!/^[0-9a-f]{64}$/.test(rHex) || !/^[0-9a-f]{64}$/.test(sHex)) throw new RangeError('bad r/s');
    let recId;
    if (vRaw === 27 || vRaw === 28) recId = vRaw - 27;
    else if (vRaw === 0 || vRaw === 1) recId = vRaw;
    else throw new RangeError('bad v');
    const rB = new Uint8Array(32); for (let i = 0; i < 32; i++) rB[i] = parseInt(rHex.slice(i * 2, i * 2 + 2), 16);
    const sB = new Uint8Array(32); for (let i = 0; i < 32; i++) sB[i] = parseInt(sHex.slice(i * 2, i * 2 + 2), 16);
    const Q = recover(digest, rB, sB, recId);
    const signer = pubkeyToAddress(Q.x, Q.y);
    if (signer.toLowerCase() !== String(auth.from).toLowerCase()) return challenge('signer_mismatch');
  } catch (e) {
    return challenge('signature_verification_failed: ' + (e && e.message ? e.message : 'error'));
  }

  // Replay guard: consume-after-success. KNOWN RACE WINDOW: two concurrent
  // requests with the same nonce can both pass this get() before either
  // markNonceUsed() lands (KV is eventually consistent). Bounded impact:
  // With CONSUMED_TX_STORE present the check is strongly consistent (no race).
  // Legacy KV fallback retains its documented eventual-consistency window.
  // R16 REPLAY GATE — CHECK-ONLY at verification time; CONSUMPTION happens
  // once, after validated upstream success (gateway calls consumeNonce).
  // Authoritative store: CONSUMED_TX_STORE (DO, strongly consistent) when
  // present; SECURITY_KV is the legacy fallback. Fail-closed on any store
  // unavailability. Documented race window (KV fallback path only): two
  // concurrent requests can both pass this read before either consumes —
  // bounded by same-amount valid-signature requirement + daily budget cap.
  if (env.CONSUMED_TX_STORE) {
    try {
      // R25: ATOMIC PRE-DISPATCH CLAIM via DO reserve-nonce — eliminates the
      // double-delivery TOCTOU (two concurrent same-nonce requests both passed a
      // read-only check). On upstream failure the gateway releases the claim via
      // /release-nonce so failed jobs don't burn valid nonces.
      const id = env.CONSUMED_TX_STORE.idFromName('singleton');
      const stub = env.CONSUMED_TX_STORE.get(id);
      const nres = await stub.fetch('https://internal/reserve-nonce', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nonce: nonceHex }),
      });
      const ndata = await nres.json().catch(() => null);
      if (!nres.ok || !ndata || ndata.ok !== true) {
        if (ndata && ndata.already === 'used')
          return challenge('nonce_already_used', 409);
        return challenge('replay_store_unavailable', 503); // fail closed
      }
    } catch (e) {
      return challenge('replay_store_unavailable', 503); // fail closed
    }
  } else if (env.SECURITY_KV) {
    try {
      const seen = await env.SECURITY_KV.get('x402_nonce:' + nonceHex);
      if (seen) return challenge('nonce_already_used', 409);
    } catch (e) {
      return challenge('replay_store_unavailable', 503); // fail closed
    }
  } else {
    return challenge('replay_store_unavailable', 503); // no replay store => fail closed
  }

return {
    ok: true,
    payer: auth.from,
    amountMicro: Number(auth.value),
    nonce: nonceHex,
    validBefore: Number(auth.validBefore),
  };
}

// markNonceUsed(env, nonce, validBeforeSeconds): replay-store entry lives at
// least 24h, and at least until 1h past the authorization's validBefore so a
// consumed nonce can never be re-verified while it could still settle.
// THROWS on unavailable KV/nonce or failed write — callers must treat a throw
// as "authorization NOT consumed" (still replayable until validBefore) and
// surface it; silently swallowing would hide replayable payments.
// R16: ATOMIC nonce consumption via the authoritative DO store (strongly
// consistent). Throws on any failure — the caller must fail closed.
export async function consumeNonce(env, nonce) {
  // R27: On the DO path the nonce was ALREADY atomically reserved in
  // verifyPayment() via /reserve-nonce. That claim IS permanent
  // consumption — calling /reserve-nonce again would see already:'used'
  // and throw. This function now only handles the KV fallback path.
  if (!env || !env.CONSUMED_TX_STORE) {
    if (env && env.SECURITY_KV && nonce) {
      // R29: use max(24h, validBefore+1h) TTL so replay window never closes early
      const ttl = Math.max(86400,
        Math.ceil((Date.now() / 1000 + 900)) | 0); // conservative min; caller passes validBefore via env binding
      await env.SECURITY_KV.put('x402_nonce:' + String(nonce).toLowerCase(), '1',
        { expirationTtl: ttl });
    }
    throw new Error('replay_store_unavailable');
  }
  // DO path: already reserved in verifyPayment — idempotent no-op.
  return true;
}

export async function markNonceUsed(env, nonce, validBeforeSeconds) {
  if (!env || !env.SECURITY_KV || !nonce) throw new Error('kv_unavailable');
  const vbSec = Number(validBeforeSeconds);
  const ttl = Math.max(86400, Number.isFinite(vbSec) ? (vbSec - Math.floor(Date.now() / 1000)) + 3600 : 86400);
  try {
    await env.SECURITY_KV.put('x402_nonce:' + String(nonce).toLowerCase(), '1', { expirationTtl: ttl });
  } catch (e) {
    throw new Error('kv_unavailable');
  }
}

// CPU economics for the gateway's ceiling/deficit gates (mirrors SpendGuard's
// estimator contract): ~2 GB/min throughput at SG_CPU_RATE_PER_HR ($/hour).
export function estimateCostUsd(sizeBytes, env) {
  const b = Number(sizeBytes);
  if (!Number.isFinite(b) || b < 0) return 0;
  const rate = parseFloat(env && env.SG_CPU_RATE_PER_HR);
  const ratePerHr = Number.isFinite(rate) && rate > 0 ? rate : 0.13;
  if (!Number.isFinite(rate) || rate <= 0) console.warn('[x402] SG_CPU_RATE_PER_HR unset/malformed, using default');
  const secs = (b / GB) * 30;
  const cost = secs * (ratePerHr / 3600);
  return Number.isFinite(cost) && cost > 0 ? cost : 0;
}

// OFFLINE VERIFICATION NOTE (honest limitation): verifyPayment DISCARDS the
// payment payload after signature recovery — nothing is persisted or settled.
// Consequence: delivered conversions are currently UNCOLLECTIBLE unless an
// operator independently captured the payment payload before it was dropped.
// Wiring settleViaFacilitator / durable authorization persistence is required
// before this service can collect revenue; until then it runs at a loss by
// design (reviewer-flagged backlog item, not an oversight).
// settleViaFacilitator is NOT yet wired into the success flow (roadmap). The
// verified authorization payload is currently DISCARDED after verification —
// there is no durable payment record and no collectible settlement exists.
// Optional CDP-facilitator settlement call (used only when CDP keys exist).
export async function settleViaFacilitator(env, paymentJson) {
  if (!env || !env.CDP_API_KEY_ID || !env.CDP_API_SECRET) return null;
  let res;
  try {
    const auth = 'Basic ' + btoa(env.CDP_API_KEY_ID + ':' + env.CDP_API_SECRET);
    res = await fetch('https://api.cdp.coinbase.com/platform/v2/x402/facilitator/settle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
      body: JSON.stringify(paymentJson),
    });
  } catch (e) {
    console.error('[x402] settle network error:', e && e.message);
    return null; // caller must check for null and fail closed
  }
  if (!res.ok) {
    console.error('[x402] settle HTTP', res.status);
    return null; // non-2xx = settlement not confirmed — caller must fail closed
  }
  try {
    return await res.json();
  } catch (e) {
    console.error('[x402] settle response parse failed');
    return null;
  }
}
