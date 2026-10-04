// R80 regression test: an UNAUTHENTICATED caller must not move the budget.
//
// BUG: reserveDailyBudget() mutated the durable daily counter at gate (7.95),
// BEFORE verifyPayment() proved the signature at gate (8). Any caller with a
// valid multipart request and no (or a junk) payment header could therefore
// reserve against the daily cap on every call, exhausting it and making
// genuine paid jobs fail with daily_budget_exhausted. Unauthenticated callers
// could deny service to paying customers for free.
//
// Fix: the reservation now happens INSIDE settle(), which verifyPayment() only
// invokes after the authorization is verified.
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const reserveAt = src.indexOf('reserveDailyBudget(env, est, budgetTxId)');
const settleAt = src.indexOf('settle: async (_payment, info)');
const verifyAt = src.indexOf('v = await verifyPayment(env, request, {');

ok('the reservation call exists', reserveAt > 0, 'missing');
ok('verifyPayment is still present', verifyAt > 0, 'missing');
ok('the settle callback is still present', settleAt > 0, 'missing');

// --- 1. the reservation must live INSIDE settle(), after verification -------
ok('the reservation is inside settle(), not before it',
   reserveAt > settleAt,
   `reserve@${reserveAt} must be after settle@${settleAt}`);

// --- 2. it must precede the facilitator call inside the same callback -------
// R82: this used to slice a HARD-CODED 2600 characters from the `settle:`
// anchor and look for cdpVerifyAndSettle inside that window. R81 inserted 11
// lines into the callback, pushing the facilitator call past 2600, so the
// lookup returned -1 and the suite reported a failure for CORRECT production
// code (reserve@471 settle@-1). A fixed character window is not a contract:
// it breaks on any unrelated edit inside the callback. Match the CALLBACK
// BOUNDARIES by brace balance instead, so the assertion survives any insertion.
function blockAt(text, start) {
  const open = text.indexOf('{', start);
  if (open < 0) return '';
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return text.slice(start);
}
const settleBlock = blockAt(src, settleAt);
ok('the settle callback body was located by brace balance',
   settleBlock.length > 200 && /^\s*settle: async/.test(settleBlock),
   `block length ${settleBlock.length}`);
const facilitatorAt = settleBlock.indexOf('cdpVerifyAndSettle');
ok('the reservation precedes the facilitator call',
   facilitatorAt > 0 && reserveAt - settleAt < facilitatorAt,
   `reserve@${reserveAt - settleAt} settle@${facilitatorAt}`);
ok('the reservation is not preceded by any facilitator contact',
   !/cdpVerifyAndSettle/.test(settleBlock.slice(0, reserveAt - settleAt)),
   'facilitator contacted before reserving');

// --- 3. nothing before verifyPayment can move the durable counter ----------
const preVerify = src.slice(0, verifyAt);
ok('no reservation happens BEFORE verifyPayment()',
   !/reserveDailyBudget\(/.test(preVerify),
   'a pre-verification reservation remains');
// The read-only pre-check is fine and must stay -- it rejects without mutating.
ok('the read-only pre-check survives (rejects over-cap without reserving)',
   /getDailyBudget\(env\)/.test(preVerify), 'pre-check removed');

// --- 4. the budget-exhausted refusal must not look like a payment failure ---
ok('an exhausted budget returns definitelyNotSubmitted',
   /definitelyNotSubmitted:\s*true/.test(
     src.slice(reserveAt, reserveAt + 600)),
   'refusal does not mark nothing-settled');
ok('an exhausted budget is retryable, not terminal',
   /retryable:\s*true/.test(src.slice(reserveAt, reserveAt + 600)),
   'not marked retryable');

// --- 5. release paths still reconcile the SAME transaction id --------------
ok('budgetTxId is still assigned once and reused',
   (src.match(/budgetTxId = 'conv-/g) || []).length === 1,
   'budgetTxId assigned more than once');
ok('releases still reconcile with the :reconcile suffix',
   /budgetTxId \+ ':reconcile'/.test(src), 'reconcile suffix lost');
ok('the oversized-header 402 still releases the reservation',
   /oversizedPaymentHeader[\s\S]{0,220}releaseReservation\(\)/.test(src),
   'release on the 402 path lost');

for (const f of fails) console.log('FAIL:', f);
console.log();
console.log(fails.length
  ? `R80-BUDGET-ORDER-FAIL (${fails.length})`
  : 'R80-BUDGET-ORDER-ALL-PASS (the daily budget is reserved only inside settle(), after the '
    + 'authorization is verified and before the facilitator call; the read-only pre-check '
    + 'still rejects over-cap callers without mutating anything)');
process.exit(fails.length ? 1 : 0);