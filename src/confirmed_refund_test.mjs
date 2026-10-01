// R37 regression test: a CONFIRMED on-chain transfer must always be refundable.
//
// BUG: after `transferConfirmed` was set (independent on-chain confirmation of
// the USDC transfer), both metadata-mismatch branches still returned a bare
// challenge. The gateway only schedules compensation when it receives
// refundRequired/paid, so a confirmed payment with mismatched or incomplete
// settlement metadata was abandoned: the payer paid and the job was dropped.
//
// Contract:
//   transferConfirmed === true  -> ALWAYS { ok:false, paid:true, refundRequired:true }
//   transferConfirmed === false -> unchanged bare challenge (retain the claim)
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./x402.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- both mismatch branches must have a refundable path ---
for (const [label, reason] of [['settlement_proof_incomplete', 'settlement_proof_incomplete'],
                               ['settlement_mismatch', 'settlement_mismatch']]) {
  const i = src.indexOf(`challenge('${reason}', 503)`);
  ok(`${label} branch located`, i > 0, 'not found');
  if (i < 0) continue;

  // Look backwards from the challenge for the guarded refundable return.
  const window = src.slice(Math.max(0, i - 900), i);
  ok(`${label}: a refundable return precedes the challenge`,
     /ok:\s*false,\s*paid:\s*true,\s*refundRequired:\s*true/.test(window),
     'no paid/refundRequired return before the challenge');
  ok(`${label}: that return is guarded on transferConfirmed`,
     /if\s*\(transferConfirmed\)/.test(window), 'refundable return is unconditional');

  // The refundable payload must carry what the gateway needs to compensate.
  ok(`${label}: carries payer, nonce and amount`,
     /payer:\s*auth\.from/.test(window) &&
     /nonce:\s*nonceHex/.test(window) &&
     /amountUsdc:\s*String\(auth\.value\)/.test(window),
     'incomplete refund payload');
  ok(`${label}: reports the correct reason`,
     new RegExp(`reason:\\s*'${reason}'`).test(window), 'reason missing');

  // The nonce must NOT be released once funds provably moved.
  ok(`${label}: does not release the nonce when transferConfirmed`,
     !/if\s*\(transferConfirmed\)\s*\{[^}]*releaseNonceClaim/.test(window),
     'releases a claim for a confirmed payment');
}

// --- the unconfirmed path must be unchanged: a bare challenge ---
{
  const i = src.indexOf("challenge('settlement_mismatch', 503)");
  const window = src.slice(Math.max(0, i - 1400), i);
  ok('the unconfirmed mismatch path still returns a bare challenge',
     /return challenge\('settlement_mismatch', 503\);/.test(src.slice(i - 40, i + 60)),
     'bare challenge missing');
  ok('release still happens only when NOT confirmed AND definitelyNotSubmitted',
     /if\s*\(!transferConfirmed\s*&&\s*s\.definitelyNotSubmitted === true\)/.test(window),
     'release guard changed');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R37-CONFIRMED-REFUND-FAIL (${fails.length})`
  : 'R37-CONFIRMED-REFUND-ALL-PASS (a confirmed transfer always returns ' +
    'paid:true/refundRequired:true with payer+nonce+amount; the unconfirmed path is ' +
    'unchanged and the claim is never released for collected money)');
process.exit(fails.length ? 1 : 0);
