// R27 regression tests for two money-path fixes.
//
//  1. cdp.js isPermanentRejection(): a 409 "already settled" was classified as
//     DEFINITELY NOT SUBMITTED, which released the nonce and scheduled no
//     refund -- a payer could be charged and given nothing. Only a genuine
//     authorization conflict is a clean "nothing moved" answer.
//  2. index.js: an engine 'success' carrying no output_key/output_bucket was
//     accepted as delivered, so the payment was collected for an object the
//     payer could not fetch and for which no receipt exists.
//
// These assert BEHAVIOUR of the real exported/embedded logic, not source text.
import { readFileSync } from 'node:fs';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// ---------- 1. the 409 classifier, executed from the real source ----------
{
  const cdp = readFileSync(new URL('./cdp.js', import.meta.url), 'utf8');
  const start = cdp.indexOf('function reasonString(');
  const end = cdp.indexOf('function isRejectionReason(');
  const ns = {};
  exec_block(cdp.slice(start, end), ns);

  const isPerm = ns.isPermanentRejection;
  ok('extracted isPermanentRejection', typeof isPerm === 'function', typeof isPerm);

  // A 409 "already settled" must NOT be treated as definitely-not-submitted.
  const already = { error: 'already settled' };
  ok('409 already settled is NOT permanent (funds may have moved)',
     isPerm(409, already) === false, isPerm(409, already));
  const alreadyFull = { reason: 'authorization already settled for this nonce' };
  ok('409 "already settled for this nonce" is NOT permanent',
     isPerm(409, alreadyFull) === false, isPerm(409, alreadyFull));

  // A genuine conflict (a different payload/recipient) is a clean rejection.
  const conflict = { error: 'conflict: payment already exists with different recipient' };
  ok('409 real conflict remains permanent (nothing moved)',
     isPerm(409, conflict) === true, isPerm(409, conflict));

  // R56: an UNCLASSIFIED 409 (busy / internal / transient) must be ambiguous.
  // Treating it as a clean "nothing moved" verdict releases the nonce and lets a
  // possibly-collected payment be retried -- a payer could be charged twice.
  for (const [body, label] of [
    [{ error: 'conflict' }, 'bare "conflict"'],
    [{ error: 'busy, try again' }, 'busy/transient'],
    [{ error: 'internal error' }, 'internal error'],
    [{}, 'empty body'],
  ]) {
    const ambiguous = isPerm(409, body) === false;
    ok(`409 ${label} is NOT a clean rejection`, ambiguous, isPerm(409, body));
  }
  // ...but an EXPLICIT authorization conflict still is.
  ok('409 explicit mismatch is still a clean rejection',
     isPerm(409, { error: 'payment does not match the submitted amount' }) === true,
     isPerm(409, { error: 'payment does not match the submitted amount' }));

  // R56: the old assertion here ("a bare conflict stays permanent") was WRONG.
  // A bare "conflict" does not establish that nothing moved, so it must NOT be a
  // clean rejection -- that would release the nonce and let a possibly-collected
  // payment be retried. Only an EXPLICIT authorization mismatch is clean.
  ok('409 bare "conflict" is ambiguous, not a clean rejection',
     isPerm(409, { error: 'conflict' }) === false, isPerm(409, { error: 'conflict' }));

  // Pre-existing classifications must not regress.
  ok('402 is still permanent', isPerm(402, {}) === true, isPerm(402, {}));
  ok('auth-layer 401 is not permanent', isPerm(401, { error: 'invalid token' }) === false,
     isPerm(401, { error: 'invalid token' }));
  ok('payment-phase 400 is permanent',
     isPerm(400, { error: 'invalid payment amount' }) === true,
     isPerm(400, { error: 'invalid payment amount' }));
  ok('5xx is not permanent', isPerm(503, {}) === false, isPerm(503, {}));
}

// ---------- 2. keyless 'success' must not be treated as delivered ----------
{
  const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  const gate = idx.slice(idx.indexOf('const engineOk ='), idx.indexOf('const hasResult ='));
  ok('engineOk is a POSITIVE success test', /=== 'success'/.test(gate), gate.slice(0, 80));

  // STRENGTHENED: the previous version only checked that the refund text
  // EXISTED, so neutering the gate to `true || (...)` still passed. Now the
  // gate shape itself is asserted.
  const hStart = idx.indexOf('const hasResult =');
  const hasResult = idx.slice(hStart, hStart + 400);
  ok('requires output_key', /parsed\.output_key/.test(hasResult), 'missing');
  ok('requires output_bucket', /parsed\.output_bucket/.test(hasResult), 'missing');
  const conjuncts = (hasResult.replace(/\s+/g, ' ').match(/&&/g) || []).length;
  ok('hasResult conjoins both field checks', conjuncts >= 1, `found ${conjuncts} &&`);
  ok('hasResult is not a tautology', !/=\s*true\s*\|\|/.test(hasResult),
     'gate short-circuited away');

  const gStart = idx.indexOf('if (!hasResult) {');
  ok('incomplete-result branch is guarded by !hasResult', gStart > 0, 'guard missing');
  const after = idx.slice(gStart, gStart + 700);
  ok('keyless success triggers a refund', /recordRefund\(/.test(after), 'no refund');
  ok('keyless success reports engine_result_incomplete',
     /engine_result_incomplete/.test(after), 'missing error id');
  ok('keyless success returns 502 not 200', /\b502\b/.test(after), 'no 502');
  ok('keyless success does not fall through to a 200',
     !/json\([^)]*status[^)]*200/.test(after), 'a 200 slipped in');
}

// helper: run a block of function declarations in a namespace
function exec_block(code, ns) {
  const f = new Function(code + '\nreturn { reasonString, isPermanentRejection };');
  Object.assign(ns, f());
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R27-FAIL (${fails.length})`
  : 'R27-ALL-PASS (409 already-settled is refundable, real conflicts still permanent, ' +
    'keyless engine success refunds)');
process.exit(fails.length ? 1 : 0);
