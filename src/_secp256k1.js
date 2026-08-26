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
