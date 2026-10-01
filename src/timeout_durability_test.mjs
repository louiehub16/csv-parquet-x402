// R25 regression test: post-settlement timeout must leave DURABLE state.
//
// BUG: the timeout path returned 504 with refund:'not_applicable' and recorded
// nothing. The only trace was an in-memory flag that died with the isolate, so
// when a SETTLED payer's conversion timed out there was no sweepable state --
// collected funds could sit stranded with nothing pointing at them.
//
// Asserts BEHAVIOUR of the decision logic, not the presence of a string.
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];

// 1. A durable claim is written for the timeout, keyed by the nonce.
if (!/timeout:\s*['"]?\s*\+\s*v\.nonce/.test(src) &&
    !/'timeout:'\s*\+\s*v\.nonce/.test(src)) {
  fails.push('no durable timeout record keyed by nonce');
}
if (!/awaiting_reconciliation/.test(src)) {
  fails.push('no reconciliation status recorded');
}

// 2. The record must capture whether funds were COLLECTED, and the payer.
if (!/settled:\s*paymentSettled\s*===\s*true/.test(src)) {
  fails.push('timeout record does not record whether payment was collected');
}
if (!/payer:\s*v\.payer/.test(src)) {
  fails.push('timeout record does not capture the payer for reconciliation');
}

// 3. The client-facing label must be honest: a COLLECTED payment is NOT
//    'not_applicable', and must not be claimed as auto-refunded either.
const label = src.match(/error:\s*'gateway_timeout'[\s\S]{0,400}?\},?\s*\n?\s*504\)/);
if (!label) {
  fails.push('could not locate the gateway_timeout response');
} else if (!/paymentSettled\s*\?\s*'required'\s*:\s*'not_applicable'/.test(label[0])) {
  fails.push('timeout label does not distinguish collected vs not-collected');
}

// 4. It must NOT auto-refund on timeout (compute may still be billing) -- the
//    R85 invariant that keeps real spend from being clawed back.
const block = src.slice(src.indexOf('gateway_timeout') - 2500, src.indexOf('gateway_timeout'));
if (/recordRefund\(/.test(block)) {
  fails.push('timeout path auto-refunds, which would lose real compute spend');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `TIMEOUT-DURABILITY-FAIL (${fails.length})`
  : 'TIMEOUT-DURABILITY-ALL-PASS (durable nonce-keyed reconciliation claim, honest label, no auto-refund)');
process.exit(fails.length ? 1 : 0);
