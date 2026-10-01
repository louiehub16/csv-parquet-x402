// Selftest for _staging/x402.js + _secp256k1.js — known-answer vectors.
import {
  keccak256, tierForBytes, buildChallenge, decodePayment,
  domainSeparator, twaDigest, pubkeyToAddress, USDC_ON_BASE, verifyPayment,
} from './x402.js';
import { recover, hexToBigInt, N, bigIntToBytes32, bytesToBigInt, scalarMult, G } from './_secp256k1.js';
import { deficitCheck } from './spendguard.js';




const GB = 1073741824;
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
// R41: settlement proof must bind payer/recipient/amount/nonce; derive them
// from the payload actually passed in so the stub stays honest.
const confirmStub = async () => ({ confirmed: true });

const settleStub = async (payment) => {
  const a = (payment && payment.payload && payment.payload.authorization) || {};
  return { ok: true, settledTx: '0x' + 'cd'.repeat(32),
    settledFrom: a.from, settledTo: a.to,
    settledAmountUsdc: String(a.value), settledNonce: a.nonce };
};

const eq = (a, b, name) => {
  if (String(a) !== String(b)) { console.error(`FAIL ${name}: got ${a} want ${b}`); process.exit(1); }
  console.log('PASS', name);
};

// --- keccak256 known answers (eth_utils oracle, verified 2026-08-23) ---
eq(bytesToHex(keccak256(new Uint8Array(0))),
   'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', 'keccak(empty)');
eq(bytesToHex(keccak256(new TextEncoder().encode('abc'))),
   '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45', 'keccak(abc)');
eq(bytesToHex(keccak256(new TextEncoder().encode('A'.repeat(300)))),
   '51657c3da406210872010d873a21919dfc4f02f52754c3164acb6855375a899c', 'keccak(300B multi-block)');
eq(bytesToHex(keccak256(new TextEncoder().encode('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'))),
   '8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f', 'keccak(domain typestring)');

// --- pricing tiers ---
eq(tierForBytes(50 * 1048576).microUsdc, 10000, 'tier <100MB flat');
eq(tierForBytes(2 * 1073741824).microUsdc, 200000, 'tier 2GB = $0.20');
eq(tierForBytes(11 * 1073741824).requiresUserDest, true, 'tier 11GB BYO');
eq(tierForBytes(11 * 1073741824).microUsdc, 550000, 'tier 11GB = $0.55');
eq(tierForBytes(150 * 1073741824).microUsdc, 150 * 15000, 'tier 150GB @ $0.015');
eq(tierForBytes(2048 * 1073741824).microUsdc, Math.ceil(2048) * 8000, 'tier 2TB @ $0.008');

// --- challenge + decode ---
const ch = buildChallenge({ url: 'https://x/v1/compress', description: 'd', microUsdc: 10000, payTo: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83' });
eq(ch.status, 402, 'challenge status');
if (!ch.headers.get('PAYMENT-REQUIRED')) { console.error('FAIL header'); process.exit(1); }
console.log('PASS challenge PAYMENT-REQUIRED header present');
const dec = decodePayment(ch.headers.get('PAYMENT-REQUIRED'));
eq(dec.accepts[0].amount, '10000', 'manifest roundtrip amount');
eq(dec.x402Version, 2, 'manifest version');

// --- ECDSA recovery: minted vector (independently verified in python) ---
const zHex  = 'dbc64ad4c00d96955f88b8b9ea32f554692a0185cec791b4e8ae1cc1412f7dc2';
const rHex  = 'b14eee9dbe0dd3ed58568b0806d9009434a591555d9504a7cf0863f7d7ee35d5';
const sHex  = '2ae4e568537d51b773958019533298bd10a87f772473c331d171c04b5db0f2c3';
const qxHex = 'f8c42f688f57a1ccae55e508961f4fb58a8dfa1242e3e9018034b25f7bb08913';
const qyHex = 'c6292f2cbc87f2122e8f7844463a56437ab26755eae15a2fa0ac6c0b849da701';
const h = (s) => { const a = new Uint8Array(32); for (let i = 0; i < 32; i++) a[i] = parseInt(s.slice(i*2, i*2+2), 16); return a; };
const Q = recover(h(zHex), h(rHex), h(sHex), 0);
eq(Q.x.toString(16), BigInt('0x' + qxHex).toString(16), 'recover Q.x');
eq(Q.y.toString(16), BigInt('0x' + qyHex).toString(16), 'recover Q.y');

// wrong recId must NOT produce the same key
let flipped = false;
try { const Q2 = recover(h(zHex), h(rHex), h(sHex), 1); flipped = Q2.x !== Q.x; } catch (e) { flipped = true; }
eq(flipped, true, 'recId flip changes/invalidates recovery');

// garbage inputs throw (fail-closed)
let threw = false;
try { recover(new Uint8Array(31), h(rHex), h(sHex), 0); } catch (e) { threw = true; }
eq(threw, true, 'short hash rejected');

// malleable high-s twin (s_high = N - s) must THROW: USDC/OpenZeppelin ECDSA
// rejects high-s on-chain, so local recovery must too (low-s enforcement).
let highSThrew = false;
try {
  const sHigh = N - BigInt('0x' + sHex);
  recover(h(zHex), h(rHex), bigIntToBytes32(sHigh), 0);
} catch (e) { highSThrew = true; }
eq(highSThrew, true, 'high-s (malleable) signature rejected');

// --- R5: unified requirements-object validation + strict CAIP-2 network ---
// Mint GENUINE signatures with the module's own curve primitives, so any
// rejection below can only be explained by the named field — never by crypto.
const MERCHANT = '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83';
const kvSeen = new Set();
const claimedNonces = new Set();
const vpEnv = {
  MERCHANT_WALLET_ADDRESS: MERCHANT,
  SECURITY_KV: { get: async (k) => (kvSeen.has(k) ? '1' : null), put: async (k) => kvSeen.add(k) },
  // R33: replay guard now REQUIRES the atomic DO store; a KV-only env must 503.
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
const mkReq = (headerVal) => ({
  url: 'https://selftest.example/v1/compress',
  headers: {
    get: (n) => (/^(PAYMENT-SIGNATURE|X-PAYMENT)$/i.test(String(n)) ? headerVal : null),
  },
});
const inv = (a, m) => { // modular inverse (extended Euclid), fail-closed
  let [or_, r] = [((a % m) + m) % m, m], [os, s] = [1n, 0n];
  while (r !== 0n) {
    const q = or_ / r;
    [or_, r] = [r, or_ - q * r];
    [os, s] = [s, os - q * s];
  }
  if (or_ !== 1n) throw new RangeError('no modular inverse');
  return ((os % m) + m) % m;
};
function signDigest(zBytes, dPriv) { // deterministic low-s ECDSA via curve ops
  const z = bytesToBigInt(zBytes);
  for (let i = 1; i < 100; i++) {
    const k = (bytesToBigInt(keccak256(new TextEncoder().encode('r5-k-' + i))) % (N - 1n)) + 1n;
    const R = scalarMult(k, G);
    if (!R || R.y === 0n) continue;
    const rr = ((R.x % N) + N) % N;
    if (rr === 0n) continue;
    let ss = (inv(k, N) * ((z + rr * dPriv) % N)) % N;
    let recId = Number(R.y & 1n);
    if (ss === 0n) continue;
    if (ss > N / 2n) { ss = N - ss; recId = 1 - recId; } // negate s <=> negate R
    return { r: rr, s: ss, v: 27 + recId };
  }
  throw new Error('signing loop exhausted');
}
const hex64 = (n) => n.toString(16).padStart(64, '0');
const b64urlJson = (o) => Buffer.from(JSON.stringify(o), 'utf8')
  .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

{
  const now = Math.floor(Date.now() / 1000);
  const dPriv = (bytesToBigInt(keccak256(new TextEncoder().encode('r5-selftest-key'))) % (N - 1n)) + 1n;
  const Qd = scalarMult(dPriv, G);
  const payer = pubkeyToAddress(Qd.x, Qd.y);
  function buildPayment(label) {
    const auth = {
      from: payer,
      to: MERCHANT,
      value: '10000',
      validAfter: now - 60,
      validBefore: now + 540,
      nonce: '0x' + bytesToHex(keccak256(new TextEncoder().encode('r5-nonce-' + label))),
    };
    const sig = signDigest(twaDigest(auth), dPriv);
    const chk = recover(twaDigest(auth), bigIntToBytes32(sig.r), bigIntToBytes32(sig.s), sig.v - 27);
    if (pubkeyToAddress(chk.x, chk.y).toLowerCase() !== payer.toLowerCase()) {
      throw new Error('minted signature failed self-check');
    }
    return {
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      accepted: { scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: MERCHANT, maxTimeoutSeconds: 600 },
      payload: { authorization: auth, signature: { r: '0x' + hex64(sig.r), s: '0x' + hex64(sig.s), v: sig.v } },
    };
  }

  // Control: the canonical-network twin of the SAME genuine-signature pipeline
  // is accepted end-to-end — proves the vectors below are rejected purely for
  // the named field, not for a broken signature.
  const ctrl = await verifyPayment(vpEnv, mkReq(b64urlJson(buildPayment('control'))),
    { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  eq(ctrl.ok, true, 'R5 control: canonical genuine payload accepted');

  // Vector A: genuine-signature payload carrying human alias network:'base'
  // must fail closed as unsupported_network under strict CAIP-2 (R4 decision).
  const pAlias = buildPayment('alias');
  // R6 contract: top-level copy CONFLICTING with accepted => conflicting_requirements;
  // alias inside accepted itself => unsupported_network.
  pAlias.network = 'base';
  const vConflict = await verifyPayment(vpEnv, mkReq(b64urlJson(pAlias)),
    { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  eq(vConflict.ok === false && vConflict.reason, 'conflicting_requirements', "R6 top-level conflict rejected as conflicting_requirements");
  const pAlias2 = buildPayment('alias2');
  pAlias2.accepted.network = 'base';
  const vAlias = await verifyPayment(vpEnv, mkReq(b64urlJson(pAlias2)),
    { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  eq(vAlias.ok === false && vAlias.reason, 'unsupported_network', "R5/R6 alias network:'base' inside accepted rejected");

  // Vector B: accepted[] requirements object whose amount conflicts with the
  // expected tier price must fail closed as amount_mismatch even though
  // auth.value itself still matches.
  const pReq = buildPayment('reqamt');
  pReq.accepted = { scheme: 'exact', network: 'eip155:8453', asset: USDC_ON_BASE, amount: '10001', payTo: MERCHANT };
  const vReq = await verifyPayment(vpEnv, mkReq(b64urlJson(pReq)),
    { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
  eq(vReq.ok === false && vReq.reason, 'amount_mismatch', 'R5 reqObj amount mismatch rejected');

  // R6 vectors: tier boundary inclusivity + accepted-object mandate
  eq(tierForBytes(10 * GB).microUsdc, 1000000, 'tier exactly 10 GiB at $0.10/GB');
  eq(tierForBytes(100 * GB).microUsdc, 5000000, 'tier exactly 100 GiB at $0.05/GB');
  eq(tierForBytes(1024 * GB).microUsdc, 15360000, 'tier exactly 1 TiB at $0.015/GB');
  {
    const pNoAcc = buildPayment('noacc');
    delete pNoAcc.accepted;
    const vNoAcc = await verifyPayment(vpEnv, mkReq(b64urlJson(pNoAcc)),
      { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
    eq(vNoAcc.ok === false && vNoAcc.reason, 'malformed_requirements', "missing accepted rejected as malformed_requirements");
    const pArr = buildPayment('arracc');
    pArr.accepted = [pArr.accepted];
    const vArr = await verifyPayment(vpEnv, mkReq(b64urlJson(pArr)),
      { expectedAmount: '10000', description: 'selftest', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
    eq(vArr.ok === false && vArr.reason, 'malformed_requirements', "array accepted rejected");
  }
  // R35: a zero expected price must never unlock paid service.
  {
    const ctrl = await verifyPayment(vpEnv, mkReq(b64urlJson(buildPayment('zeroprice'))),
      { expectedAmount: '0', settle: settleStub, confirm: confirmStub, sizeBytes: 1000 });
    eq('false', String(ctrl.ok), 'zero-price authorization rejected (ok must be false)');
    if (ctrl.ok === false) console.log('   reason:', ctrl.reason);
  }
}



// R24: deficitCheck BigInt micro-unit compare
eq(deficitCheck(0.01, 10000n).ok, true, 'deficitCheck(0.01, 10000n) passes');
eq(deficitCheck(0.01, 9999n).status, 402, 'deficitCheck(0.01, 9999n) fails 402');

console.log('SELFTEST-ALL-PASS');
