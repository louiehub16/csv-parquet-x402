// R26: recover the signer of a TransferWithAuthorization.
//
// Exported so the result-retrieval endpoint re-verifies the SAME EIP-712
// signature the money path already enforces, instead of trusting a header
// whose nonce is public on-chain. Delegates to the existing primitives so
// there is exactly ONE signature-verification implementation in the codebase.
import {
  twaDigest, pubkeyToAddress, recover,
} from './x402.js';
import { readFileSync } from 'node:fs';

const HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

function hex32(hex) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * @returns {string|null} the recovered signer address, or null if the
 *   signature is missing/malformed/high-s/does not recover.
 */
export function recoverAuthorizationSigner(auth, sig) {
  try {
    if (!auth || !sig) return null;
    let rHex, sHex, vRaw;
    if (typeof sig === 'string') {
      const raw = String(sig).toLowerCase().replace(/^0x/, '');
      if (raw.length !== 130) return null;
      rHex = raw.slice(0, 64); sHex = raw.slice(64, 128); vRaw = parseInt(raw.slice(128, 130), 16);
    } else {
      rHex = String(sig.r).toLowerCase().replace(/^0x/, '');
      sHex = String(sig.s).toLowerCase().replace(/^0x/, '');
      vRaw = sig.v != null ? Number(sig.v) : (sig.recovery != null ? Number(sig.recovery) : undefined);
    }
    if (!/^[0-9a-f]{64}$/.test(rHex) || !/^[0-9a-f]{64}$/.test(sHex)) return null;
    // EIP-2: USDC/OpenZeppelin reject high-s, so a high-s signature is unusable.
    if (BigInt('0x' + sHex) > HALF_N) return null;
    let recId;
    if (vRaw === 27 || vRaw === 28) recId = vRaw - 27;
    else if (vRaw === 0 || vRaw === 1) recId = vRaw;
    else return null;
    const digest = twaDigest({
      from: auth.from, to: auth.to, value: auth.value,
      validAfter: auth.validAfter, validBefore: auth.validBefore,
      nonce: String(auth.nonce).replace(/^0x/, '').toLowerCase(),
    });
    const Q = recover(digest, hex32(rHex), hex32(sHex), recId);
    return pubkeyToAddress(Q.x, Q.y);
  } catch (e) {
    return null;
  }
}
