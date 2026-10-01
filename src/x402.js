// x402 v2 SELLER-side payment module (Cloudflare Worker compatible, zero deps).
// - Tier pricing (micro-USDC integers; USDC on Base has 6 decimals)
// - HTTP 402 PAYMENT-REQUIRED challenge manifest (x402scan/CDP-Bazaar parseable)
// - EIP-712 TransferWithAuthorization verification against USDC on Base,
//   with offline secp256k1 signer recovery + KV replay guard.
// FAIL-CLOSED: any malformed/missing/expired/tampered payment rejects.
import {
  recover, hexToBigInt, bigIntToBytes32, bytesToBigInt,
} from './_secp256k1.js';

// R26: re-export the primitives so every caller (the money path and the
// result-retrieval path) shares ONE signature-verification implementation.
export { recover };

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
  // R37: values above 2^53 lose byte precision when coerced through Number,
  // which would undercharge an oversized upload. Reject rather than price
  // something we cannot count exactly.
  if (!Number.isSafeInteger(b)) throw new RangeError('size exceeds exact integer range');
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

// UTF-8 SAFE base64url: btoa() throws on code points > 0xFF (e.g. a Unicode
// description), which would surface as an unhandled 500 instead of a priced 402.
function b64urlUtf8(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}


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
  const b64 = b64urlUtf8(manifest);
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
// R42: release a claimed nonce when settlement definitively fails, so the
// payer can retry with the same authorization instead of being locked out.
async function releaseNonceClaim(env, nonce) {
  try {
    const store = env && env.CONSUMED_TX_STORE;
    if (!store || !nonce) return;
    const stub = store.get(store.idFromName('singleton'));
    await stub.fetch('https://internal/release-nonce', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce }),
    });
  } catch (e) { /* best-effort: the client may still retry with a fresh auth */ }
}

export async function verifyPayment(env, request, opts = {}) {
  // R40: opts.settle — REQUIRED async (paymentPayload) => result. Verification
  // is not payment: this function only returns ok:true when a settlement
  // function proves the transfer. Callers must not treat a bare signature
  // check as a completed payment.
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
  // R35: reject a ZERO price. A zero-value authorization is well-formed and
  // would recover to the payer, but it buys nothing — serving it would hand
  // paid infrastructure away for free.
  if (!expected || !/^[0-9]+$/.test(expected) || expected === '0') {
    return challenge('unpriceable_request');
  }
  // R46: the measured size is MANDATORY. Without it, expectedAmount is the
  // client's own number and a 1-micro-USDC authorization would pass.
  if (opts.sizeBytes == null) return challenge('unpriceable_request');
  let authoritative;
  try {
    authoritative = tierForBytes(opts.sizeBytes).microUsdc;
  } catch (e) {
    return challenge('unpriceable_request');
  }
  if (String(authoritative) !== String(expected)) return challenge('price_mismatch', 400);

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
  // R38: the challenge advertises maxTimeoutSeconds=600, so an
  // authorization window longer than that contradicts our own manifest.
  if (!Number.isInteger(vb - va) || vb - va > 600) return challenge('time_window_violation');
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
    // R31: enforce EIP-2 low-s HERE, not only in recover(). USDC / OpenZeppelin
    // verification rejects high-s, so a high-s signature that recovers to the
    // right signer locally would still be uncollectible on-chain.
    {
      const sBi = BigInt('0x' + sHex);
      const HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
      if (sBi > HALF) throw new RangeError('high-s signature');
    }
    let recId;
    // R43: accept the full 4-valued recovery id. 0/1 and 27/28 are the common
    // encodings; 2/3 mark R.x >= n and are mathematically valid. The 27/28 form
    // only encodes parity, so it is mapped to 0/1 (adding 2 would invent an
    // overflow that the 27/28 encoding cannot express).
    if (vRaw === 27 || vRaw === 28) recId = vRaw - 27;
    else if (vRaw >= 0 && vRaw <= 3) recId = vRaw;
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
  // unavailability.
  // R33: the replay store MUST be the strongly-consistent Durable Object. A
  // SECURITY_KV-only deployment cannot make claim+consume atomic, so two
  // concurrent requests can both pass the check and both receive paid
  // service. Fail closed instead of serving with a non-atomic guard.
  if (!env || !env.CONSUMED_TX_STORE) {
    return challenge('replay_store_unavailable', 503);
  }
  {
    try {
      // R47: validate the settlement wiring BEFORE reserving the nonce, so a
  // misconfigured caller cannot burn a valid authorization.
  if (typeof opts.settle !== 'function' || typeof opts.confirm !== 'function') {
    return challenge('settlement_unavailable', 503);
  }

  // R25: ATOMIC PRE-DISPATCH CLAIM via DO reserve-nonce — eliminates the
      // double-delivery TOCTOU (two concurrent same-nonce requests both passed a
      // read-only check). On upstream failure the gateway releases the claim via
      // /release-nonce so failed jobs don't burn valid nonces.
      // R39: optional chaining — a missing/undefined env must fail closed with
      // the same challenge, not throw a TypeError into the generic 500 path.
      const store = env && env.CONSUMED_TX_STORE;
      if (!store) return challenge('replay_store_unavailable', 503);
      const id = store.idFromName('singleton');
      const stub = store.get(id);
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
  }

  // R40: settle BEFORE declaring success. A valid signature is an unexecuted
  // promise to pay; only a confirmed settlement is payment.
  if (typeof opts.settle !== 'function') {
    return challenge('settlement_unavailable', 503);
  }
  let settlement;
  try {
    settlement = await opts.settle(payment, { nonce: nonceHex, authorization: auth });
  } catch (e) {
    // R44: a transport error here is AMBIGUOUS (the transfer may have landed),
    // so KEEP the claim — releasing invites a double-delivery race against a
    // late settlement. The client must present a FRESH authorization.
    // R39: but a bare challenge discards the payer/nonce, so the gateway's
    // catch-all has nothing to refund with and a possibly-collected payment is
    // stranded. Return the AMBIGUOUS-but-REFUNDABLE shape with the verified
    // payer and nonce preserved.
    return {
      ok: false, paid: true, refundRequired: true, settledUnknown: true,
      reason: 'settlement_failed',
      payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
    };
  }
  if (!settlement || settlement.ok !== true) {
    // R69: distinguish (a) nothing was submitted (retryable, release the claim)
    // from (b) the settler REFUSED a payment that was already taken — terminal
    // and the payer must be compensated.
    if (settlement && settlement.terminal === true) {
      return {
        ok: false, paid: true, refundRequired: true,
        reason: settlement.reason || 'settlement_failed',
        payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
      };
    }
    if (settlement && settlement.definitelyNotSubmitted === true) {
      await releaseNonceClaim(env, nonceHex);
      return challenge('settlement_unconfirmed', 503);
    }
    // R20: an AMBIGUOUS settlement (settledUnknown) means the facilitator took
    // the submission and we cannot prove whether funds moved. Returning a bare
    // 503 discarded that signal: the nonce stayed claimed, NO refund was
    // scheduled, and potentially collected USDC was stranded. Treat it exactly
    // like the other "paid but unprovable" branches — refundable, and never
    // released so the authorization cannot be replayed.
    if (settlement && (settlement.settledUnknown === true || settlement.refundRequired === true)) {
      return {
        ok: false, paid: true, refundRequired: true,
        reason: (settlement.reason || 'settlement_unconfirmed'),
        payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
      };
    }
    return challenge('settlement_unconfirmed', 503);
  }
  if (typeof settlement.settledTx !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(settlement.settledTx)) {
    // R69: settled but UNPROVABLE — the payer paid; never let this be retried.
    return {
      ok: false, paid: true, refundRequired: true, reason: 'settle_tx_unproven',
      payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
    };
  }
  // R48: once a transfer is CONFIRMED on-chain, the claim is permanent. A
  // metadata mismatch afterwards must NOT release it, or the same (already
  // paid) authorization could be replayed for a second delivery.
  let transferConfirmed = false;

  // R45: require ON-CHAIN CONFIRMATION of the settlement. The callback's own
  // claim is not proof; `opts.confirm(txHash)` must independently confirm the
  // Base transfer (status 1 + matching USDC Transfer) before we treat the
  // payment as collected. No confirm function => not proven.
  if (typeof opts.confirm === 'function') {
    let conf;
    try {
      conf = await opts.confirm(settlement.settledTx, {
        from: auth.from, to: auth.to, value: String(auth.value), nonce: nonceHex,
      });
    } catch (e) {
      // R20: the facilitator already reported success, so the money may be gone
      // even though our independent confirmation threw. Refundable, not a 503.
      return {
        ok: false, paid: true, refundRequired: true,
        reason: 'settlement_unconfirmed',
        payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
      };
    }
    if (!conf || conf.confirmed !== true) {
      // R81: the facilitator reported success, so funds were collected even
      // though our independent on-chain check could not confirm. This is a
      // refundable terminal outcome, not a plain "not paid".
      return {
        ok: false, paid: true, refundRequired: true,
        reason: 'settlement_unconfirmed',
        payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
      };
    }
    transferConfirmed = true;
  } else {
    // R20: settlement succeeded but nothing can confirm it. Funds may be
    // collected, so this must be refundable rather than a bare 503.
    return {
      ok: false, paid: true, refundRequired: true,
      reason: 'settlement_unconfirmed',
      payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
    };
  }

  // R41: BIND the receipt to the authorization we actually verified. A settle
  // implementation that returns ok with an unrelated transaction hash must not
  // unlock paid work, so the callback must echo the exact payer/recipient/
  // amount/nonce it settled. Any mismatch is a failed proof.
  {
    const s = settlement;
    const lower = (a) => String(a).toLowerCase();
    const strip0x = (a) => String(a).replace(/^0x/i, '').toLowerCase();
    // Every identity field is REQUIRED: an implementation that omits them
    // cannot be bound to the authorization, so the proof is incomplete.
    if (s.settledFrom == null || s.settledTo == null ||
        s.settledAmountUsdc == null || s.settledNonce == null) {
      // R49: release ONLY when the settler explicitly guarantees nothing was
      // submitted on-chain. A missing/garbled result is AMBIGUOUS (the transfer
      // may still broadcast), so retain the claim and require a fresh
      // authorization instead of risking a second delivery for one payment.
      if (!transferConfirmed && s.definitelyNotSubmitted === true) {
        await releaseNonceClaim(env, nonceHex);
      }
      // R37: the transfer is CONFIRMED on chain, so the payer has paid. Incomplete
      // metadata cannot undo that -- return a refundable outcome or the gateway
      // schedules no compensation and the money is stranded.
      if (transferConfirmed) {
        return {
          ok: false, paid: true, refundRequired: true,
          reason: 'settlement_proof_incomplete',
          payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
        };
      }
      return challenge('settlement_proof_incomplete', 503);
    }
    if (lower(s.settledFrom) !== lower(auth.from) ||
        lower(s.settledTo) !== lower(auth.to) ||
        lower(s.settledAmountUsdc) !== String(auth.value).toLowerCase() ||
        strip0x(s.settledNonce) !== strip0x(nonceHex)) {
      // A confirmed mismatch IS definitive (the settled transfer demonstrably
      // belongs to a different authorization) — but an UNconfirmed one is not.
      if (!transferConfirmed && s.definitelyNotSubmitted === true) {
        await releaseNonceClaim(env, nonceHex);
      }
      // R37: a CONFIRMED transfer whose metadata belongs to a DIFFERENT
      // authorization is still collected money. We must not deliver the work and
      // must not silently keep the payment -- refund it and flag the mismatch.
      if (transferConfirmed) {
        return {
          ok: false, paid: true, refundRequired: true,
          reason: 'settlement_mismatch',
          payer: auth.from, nonce: nonceHex, amountUsdc: String(auth.value),
        };
      }
      return challenge('settlement_mismatch', 503);
    }
  }

  return {
    ok: true,
    settledTx: settlement.settledTx,
    payer: auth.from,
    amountMicroUsdc: String(auth.value), // string: micro-USDC beyond 2^53 loses precision as a Number
    nonce: nonceHex,
    validBefore: Number(auth.validBefore),
    // R33: hand the caller the VERIFIED authorization and the raw envelope so
    // the settlement step can act on it. Discarding it here is exactly what
    // left accepted payments uncollectible.
    authorization: {
      from: auth.from, to: auth.to, value: String(auth.value),
      validAfter: Number(auth.validAfter), validBefore: Number(auth.validBefore),
      nonce: nonceHex,
    },
    paymentPayload: payment,
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
  // R37: DO-ONLY finalization. The SECURITY_KV fallback is gone — KV is
  // eventually consistent and cannot atomically reserve a nonce, so consuming
  // through it would permit concurrent double-delivery. If the DO is missing
  // the caller must fail closed.
  if (!env || !env.CONSUMED_TX_STORE) throw new Error('replay_store_unavailable');
  const id = env.CONSUMED_TX_STORE.idFromName('singleton');
  const stub = env.CONSUMED_TX_STORE.get(id);
  const res = await stub.fetch('https://internal/finalize-nonce', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce }),
  }).catch(() => { throw new Error('replay_store_unavailable'); });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || data.ok !== true) throw new Error('nonce_finalize_failed');
  return true;
}

// markNonceUsed — REMOVED (R37): the non-atomic KV replay fallback is gone; the
// Durable Object is the only replay store and the gateway fails closed without it.


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

// SETTLEMENT (R29): settlement IS wired. verifyPayment() requires an
// opts.settle callback and returns ok:true ONLY after that callback proves a
// confirmed on-chain transfer. The gateway passes
// cdp.js::cdpVerifyAndSettle, which performs CDP verify + settle and requires a
// provable transaction hash (plus an independent on-chain confirmation bound to
// the authorization nonce) before reporting success. There is no offline-only
// or discarded-payload path: ambiguous or unprovable outcomes are REFUNDABLE,
// never silently delivered.
// Optional CDP-facilitator settlement call (used only when CDP keys exist).
// settleViaFacilitator — REMOVED (R34).
// The only settlement implementation is cdp.js::cdpVerifyAndSettle, which
// performs verify + settle, validates the documented success indicator AND
// requires a provable transaction hash before reporting ok:true. This module
// previously carried a second, weaker stub that accepted any 2xx body as
// settlement — a paid-service-without-collection path. Do not reintroduce it;
// import cdpVerifyAndSettle instead.

