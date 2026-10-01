
import { signDigest, sha256, recover, bytesToBigInt, bigIntToBytes32 } from './_secp256k1.js';
import { keccak256 } from './x402.js';
import { readFileSync } from 'node:fs';

const hex = (b) => [...b].map(x => x.toString(16).padStart(2,'0')).join('');

let fails = 0;
const check = (n, c, x='') => { console.log((c?'PASS ':'FAIL ')+n+(x?`  [${x}]`:'')); if(!c) fails++; };

// 1) sha256 known-answer
const k = await sha256(new TextEncoder().encode('abc'));
check('sha256("abc") known-answer', hex(k) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', hex(k).slice(0,16));

// 2) keccak256 still good (regression from cdp.js import)
const kc = keccak256(new TextEncoder().encode(''));
check('keccak256("") known-answer', hex(kc) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');

// 3) sign->recover round trip (the critical one)
const privHex = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const priv = new Uint8Array(32);
for (let i=0;i<32;i++) priv[i] = parseInt(privHex.substr(i*2,2),16);
const digest = await sha256(new TextEncoder().encode('settlement test digest'));
const sig = await signDigest(digest, priv);
check('sign produced r,s', sig.r > 0n && sig.s > 0n);
check('low-s enforced', sig.s <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n,
      's<=n/2');
const Q = recover(digest, bigIntToBytes32(sig.r), bigIntToBytes32(sig.s), sig.recovery & 1);
const fromPriv = recover(bigIntToBytes32(bytesToBigInt(priv)), bigIntToBytes32(1n), bigIntToBytes32(1n), 0);
// verify recovered Q.x == priv * G x
import('./_secp256k1.js').then(async m => {
  const P = m.scalarMult(bytesToBigInt(priv), { x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
                                               y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n });
  check('recover(sig) == signer public key', Q.x === P.x && Q.y === P.y);
  console.log(fails===0 ? 'SIGN-SELFTEST-ALL-PASS' : `SIGN-SELFTEST FAILURES: ${fails}`);
  process.exit(fails===0?0:1);
});
