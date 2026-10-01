// R43 regression test: recovery must accept the full recovery-id range.
//
// BUG: recover() rejected recId 2/3 ("recId must be 0 or 1"). Those ids are
// mathematically valid -- they encode the case where the curve point R has
// x >= n, so the true x coordinate is r + n rather than r. The probability is
// ~2^-128, so this is not a practical attack, but the old code made recovery
// FAIL for a valid signature rather than returning the wrong key, and x402.js
// rejected v values of 2/3 at parse time.
//
// Asserts: ids 0/1 still work, ids 2/3 are accepted (not thrown), and the
// signer produced for the normal case is unchanged.
import { readFileSync } from 'node:fs';
import { signDigest, sha256, recover, scalarMult, G, N } from './_secp256k1.js';
// pubkeyToAddress lives in x402.js (it needs keccak256), not in the curve module.
import { pubkeyToAddress } from './x402.js';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const toBytes32 = (n) => {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
};

// --- ids 0/1 must keep working (the common case must not regress) ---
{
  let matched = 0, tried = 0;
  for (let t = 0; t < 12; t++) {
    const priv = new Uint8Array(32);
    for (let i = 0; i < 32; i++) priv[i] = (i * 17 + t * 29 + 5) & 0xff;
    priv[0] |= 1;
    let d = 0n; for (const b of priv) d = (d << 8n) | BigInt(b);
    if (d <= 0n || d >= N) continue;
    const expected = pubkeyToAddress(scalarMult(d, G).x, scalarMult(d, G).y).toLowerCase();
    const digest = await sha256(new TextEncoder().encode('r43-' + t));
    const { r, s, recovery } = await signDigest(digest, priv);
    tried++;
    ok(`t${t}: recovery id is 0 or 1`, recovery === 0 || recovery === 1, recovery);
    const Q = recover(digest, toBytes32(r), toBytes32(s), recovery);
    if (pubkeyToAddress(Q.x, Q.y).toLowerCase() === expected) matched++;
  }
  ok('all normal round trips still recover the signer', matched === tried,
     `${matched}/${tried}`);
}

// --- ids 2/3 must be ACCEPTED, not rejected as out of range ---
{
  // A real 2/3 signature is ~2^-128, so construct the input directly: recovery
  // must not throw "recId must be 0 or 1" for 2 or 3.
  const digest = await sha256(new TextEncoder().encode('r43-overflow'));
  const priv = new Uint8Array(32);
  for (let i = 0; i < 32; i++) priv[i] = (i * 5 + 3) & 0xff;
  priv[0] |= 1;
  let d = 0n; for (const b of priv) d = (d << 8n) | BigInt(b);
  const { r, s } = await signDigest(digest, priv);

  for (const recId of [2, 3]) {
    let threw = null;
    try {
      recover(digest, toBytes32(r), toBytes32(s), recId);
    } catch (e) { threw = e.message; }
    ok(`recId ${recId} is not rejected as out of range`,
       threw === null || !/recId must be 0 or 1/.test(threw), threw);
  }

  // Genuinely invalid ids must STILL be rejected (fail-closed).
  for (const recId of [4, 7, -1, 99]) {
    let threw = null;
    try { recover(digest, toBytes32(r), toBytes32(s), recId); } catch (e) { threw = e.message; }
    ok(`recId ${recId} is still refused`, /recId/.test(threw || ''), threw || 'accepted!');
  }
}

// --- the source must actually select the r+n candidate for overflow ids ---
{
  const src = readFileSync(new URL('./_secp256k1.js', import.meta.url), 'utf8');
  ok('overflow is detected from the recId', /recId\s*>=\s*2/.test(src), 'no overflow check');
  ok('the x candidate is r + n for overflow', /overflowed\s*\?\s*r\s*\+\s*N\s*:\s*r/.test(src),
     'no r+n candidate');
  ok('decompressY receives the x value and the parity, not the raw recId',
     /decompressY\(Rx,\s*parity\)/.test(src), 'still passing recId to decompressY');
  ok('parity is derived as recId & 1', /recId\s*&\s*1/.test(src), 'parity not derived');

  const x402 = readFileSync(new URL('./x402.js', import.meta.url), 'utf8');
  ok('v parsing accepts 0..3', /vRaw\s*>=\s*0\s*&&\s*vRaw\s*<=\s*3/.test(x402),
     'v parsing still limited to 0/1');
  ok('v parsing still accepts 27/28', /vRaw === 27 \|\| vRaw === 28/.test(x402),
     '27/28 handling lost');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R43-RECID-FAIL (${fails.length})`
  : 'R43-RECID-ALL-PASS (ids 0/1 round-trip correctly; 2/3 accepted with the r+n ' +
    'candidate; 4/7/-1/99 still refused; v parsing accepts 0..3 and 27/28)');
process.exit(fails.length ? 1 : 0);
