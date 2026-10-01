// R23 regression test: recovery-id correctness for ECDSA signing.
//
// BUG: signDigest() inverted the recovery parity UNCONDITIONALLY, even when the
// low-s normalization never fired. The inversion is only valid when s was
// actually flipped to n-s, so roughly half of all signatures carried the wrong
// recovery id -- the signer's own recover() could not reproduce the key, and a
// verifier (facilitator) would reject them.
//
// The decisive property is a ROUND TRIP: sign a digest, then recover the public
// key and check it equals the public key derived from the private key. This
// asserts BEHAVIOUR, not the presence of an `if`.
import { signDigest, sha256, recover, decompressY, scalarMult, G, N } from './_secp256k1.js';

function pubFromPriv(priv) {
  let d = 0n;
  for (const b of priv) d = (d << 8n) | BigInt(b);
  return scalarMult(d, G);
}

const addr = (P) => {
  const x = P.x.toString(16).padStart(64, '0');
  return x.slice(-40).toLowerCase();
};
const toBytes32 = (n) => {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
};

const fails = [];
let ok = 0, tried = 0;

for (let t = 0; t < 24; t++) {
  // distinct private keys and digests
  const priv = new Uint8Array(32);
  for (let i = 0; i < 32; i++) priv[i] = (i * 7 + t * 31 + 11) & 0xff;
  priv[0] |= 1;                       // keep it non-zero
  const digest = await sha256(new TextEncoder().encode('roundtrip-' + t));

  let d = 0n;
  for (const b of priv) d = (d << 8n) | BigInt(b);
  if (d <= 0n || d >= N) continue;
  const expected = pubFromPriv(priv);
  tried++;

  const { r, s, recovery } = await signDigest(digest, priv);

  // low-s must still hold after normalization
  if (s > N / 2n) { fails.push(`t${t}: s not normalized low`); continue; }
  if (s === 0n || r === 0n) { fails.push(`t${t}: zero r/s`); continue; }
  if (recovery !== 0 && recovery !== 1) { fails.push(`t${t}: bad recId ${recovery}`); continue; }

  let Q;
  try {
    Q = recover(digest, toBytes32(r), toBytes32(s), recovery);
  } catch (e) {
    fails.push(`t${t}: recover threw ${e.message}`);
    continue;
  }
  if (addr(Q) !== addr(expected)) {
    fails.push(`t${t}: recovered ${addr(Q)} != signer ${addr(expected)} (recId=${recovery})`);
    continue;
  }
  ok++;
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `SIGN-ROUNDTRIP-FAIL (${ok}/${tried} recovered)`
  : `SIGN-ROUNDTRIP-ALL-PASS (${ok}/${tried} sign->recover round trips matched the signer key)`);
process.exit(fails.length ? 1 : 0);
