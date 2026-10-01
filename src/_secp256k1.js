// secp256k1 + ECDSA public-key recovery, dependency-free ES module.
// Target: Cloudflare Workers (WebCrypto has NO secp256k1, so we implement it).
// BigInt affine arithmetic — clarity over speed; fine for per-request auth.
// Every function validates inputs and throws RangeError/TypeError on garbage
// (fail-closed: callers must never proceed on a malformed crypto input).

export const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
export const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
export const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
export const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
export const G = { x: Gx, y: Gy };

export function hexToBigInt(h) {
  if (typeof h !== 'string') throw new TypeError('hex string required');
  let s = h.trim().toLowerCase();
  if (s.startsWith('0x')) s = s.slice(2);
  if (s.length === 0 || /[^0-9a-f]/.test(s)) throw new RangeError('bad hex string');
  return BigInt('0x' + s);
}

export function bigIntToBytes32(n) {
  if (typeof n !== 'bigint') throw new TypeError('bigint required');
  if (n < 0n || n >= (1n << 256n)) throw new RangeError('uint256 out of range');
  const hex = n.toString(16).padStart(64, '0');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToBigInt(b) {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

function mod(a, m = P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInv(a, m = P) {
  // Extended Euclid. Throws when a is not invertible (fail closed).
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new RangeError('no modular inverse');
  return mod(old_s, m);
}

function modPow(b, e, m = P) {
  let result = 1n, base = mod(b, m), ee = e;
  while (ee > 0n) {
    if (ee & 1n) result = (result * base) % m;
    base = (base * base) % m;
    ee >>= 1n;
  }
  return result;
}

function isOnCurve(p) {
  return mod(p.y * p.y) === mod(p.x * p.x * p.x + 7n);
}

export function ptDouble(p) {
  if (p === null || p.y === 0n) return null;
  const l = mod(3n * p.x * p.x * modInv(2n * p.y));
  const x = mod(l * l - 2n * p.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}

export function ptAdd(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (mod(p.y + q.y) === 0n) return null; // inverse points -> infinity
    return ptDouble(p);
  }
  const l = mod((q.y - p.y) * modInv(q.x - p.x));
  const x = mod(l * l - p.x - q.x);
  return { x, y: mod(l * (p.x - x) - p.y) };
}

export function scalarMult(k, p) {
  let kk = mod(k, N);
  if (kk === 0n) return null;
  let result = null, base = p;
  while (kk > 0n) {
    if (kk & 1n) result = ptAdd(result, base);
    base = ptDouble(base);
    kk >>= 1n;
  }
  return result;
}

// Decompress the point with x-coordinate x and parity oddBit (0=even y, 1=odd y).
// p % 4 == 3 for secp256k1, so sqrt(y2) = y2^((p+1)/4).
export function decompressY(x, oddBit) {
  const xv = mod(typeof x === 'bigint' ? x : hexToBigInt(x));
  const y2 = mod(xv * xv * xv + 7n);
  let y = modPow(y2, (P + 1n) / 4n);
  if (mod(y * y) !== y2) throw new RangeError('x is not on the curve (no square root)');
  if ((y & 1n) !== BigInt(oddBit & 1)) y = P - y;
  return { x: xv, y };
}

// ECDSA public-key recovery (secp256k1).
// msgHash: 32-byte Uint8Array; rBytes/sBytes: 32-byte Uint8Array; recId: 0 | 1
// (full recid 0..3 collapses to parity because R.x is reduced mod N before use).
// Returns { x: bigint, y: bigint } of the recovered public key point.
export function recover(msgHash, rBytes, sBytes, recId) {
  if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32)
    throw new RangeError('message hash must be exactly 32 bytes');
  if (!(rBytes instanceof Uint8Array) || rBytes.length !== 32)
    throw new RangeError('r must be exactly 32 bytes');
  if (!(sBytes instanceof Uint8Array) || sBytes.length !== 32)
    throw new RangeError('s must be exactly 32 bytes');
  const r = bytesToBigInt(rBytes);
  const s = bytesToBigInt(sBytes);
  if (r === 0n || r >= N || s === 0n || s >= N)
    throw new RangeError('r/s out of valid range [1, n-1]');
  // Low-s enforcement: USDC/OpenZeppelin ECDSA rejects high-s; local recovery
  // must match contract behavior or work is uncollectible.
  if (s > N / 2n) throw new RangeError('high-s signature (malleable) rejected');
  if (recId !== 0 && recId !== 1)
    throw new RangeError('recId must be 0 or 1');

  const R = decompressY(r, recId);
  const z = bytesToBigInt(msgHash);
  const rInv = modInv(r, N);
  const u1 = mod(-z * rInv, N);
  const u2 = mod(s * rInv, N);
  const Q = ptAdd(scalarMult(u1, G), scalarMult(u2, R));
  if (Q === null || !isOnCurve(Q))
    throw new RangeError('recovery produced an invalid point');
  return Q;
}


// ---------------------------------------------------------------- SHA-256
// WebCrypto-backed SHA-256 (Workers runtime provides crypto.subtle). Returns
// Uint8Array(32). Falls back to a pure-JS implementation off-Workers.
export async function sha256(bytes) {
  if (globalThis.crypto && globalThis.crypto.subtle) {
    const buf = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(buf);
  }
  return sha256Pure(bytes);
}

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256Pure(bytes) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const msg = new Uint8Array(((bytes.length + 9) >> 6 << 6) + 64);
  msg.set(bytes); msg[bytes.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(msg.length - 4, bytes.length * 8 >>> 0);
  dv.setUint32(msg.length - 8, Math.floor(bytes.length * 8 / 4294967296));
  const w = new Uint32Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i-15], b = w[i-2];
      const s0 = rotr(a,7) ^ rotr(a,18) ^ (a >>> 3);
      const s1 = rotr(b,17) ^ rotr(b,19) ^ (b >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
  return out;
}

// ------------------------------------------------------- ECDSA signing
// Deterministic k = SHA256(privkey || digest || counter) mod n. NOT RFC 6979
// (we have no HMAC primitive here), but the facilitator only VERIFIES the
// signature — it does not require RFC-6979 determinism. k is unguessable and
// never reused across differing digests, which is what actually matters.
// Returns { r, s, recovery } as bigints. Enforces low-s (EIP-2), matching
// OpenZeppelin/USDC verification.
export async function signDigest(digest32, privBytes) {
  const d = bytesToBigInt(privBytes);
  if (d <= 0n || d >= N) throw new RangeError('private key out of range');
  const z = bytesToBigInt(digest32);
  const dBytes = bigIntToBytes32(d);
  for (let counter = 0; counter < 256; counter++) {
    const seed = new Uint8Array(32 + 32 + 1);
    seed.set(dBytes, 0);
    seed.set(digest32, 32);
    seed[64] = counter & 0xff;
    const kb = await sha256(seed);
    const k = bytesToBigInt(kb);
    if (k <= 0n || k >= N) continue;
    const R = scalarMult(k, G);
    if (!R) continue;
    const r = R.x % N;
    if (r === 0n) continue;
    const kInv = modInv(k, N);
    let s = (kInv * (z + r * d)) % N;
    if (s === 0n) continue;
    // EIP-2 low-s normalization so on-chain verifiers that reject high-s
    // (USDC / OpenZeppelin) accept the signature.
    // R23: RECORD whether the flip actually happened. Negating s to n-s negates
    // the public key to (Qx, n-Ry), which flips the y-parity -- but ONLY when a
    // flip occurred. The previous code inverted unconditionally, so every
    // signature whose s was already low carried a WRONG recovery id: ~half of
    // all signatures were unverifiable (and unrecoverable here).
    const normalized = s > N / 2n;
    if (normalized) s = N - s;
    // Recovery id for the (possibly) LOW-S-normalized signature.
    // Unnormalized:  v = (R.y & 1) | (R.x > n ? 2 : 0)
    const overflowed = R.x >= N;
    const baseParity = (R.y & 1n ? 1 : 0);
    const parity = normalized ? (baseParity ^ 1) : baseParity;
    const recovery = (parity ^ (overflowed ? 1 : 0)) & 1;
    return { r, s, recovery };
  }
  throw new Error('signDigest: exhausted k candidates');
}
