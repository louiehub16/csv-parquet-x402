// R79 regression test: a client disconnect is NOT a timeout.
//
// BUG: the client's request-signal abort and our own timeout both fired the same
// AbortController, so the AbortError branch could not tell them apart. A client
// that hung up AFTER settlement but BEFORE dispatch left the engine untouched --
// no compute, no output -- yet the request took the timeout path, recorded
// `awaiting_reconciliation` instead of refunding, and reported refund:'required'.
// The payer was charged for work that never ran, and the operator sweep was asked
// to reconcile a job that never started.
//
// The two events now differ:
//   client disconnect, engine never accepted -> durable refund (or release)
//   our own timeout, engine may still billing -> reconciliation, NO auto-refund
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- 1. the two abort causes are distinguished -----------------------------
ok('a client-abort flag exists', /let abortedByClient = false/.test(src), 'missing');
ok('the request-signal listener sets it',
   /const onAbort = \(\) => \{\s*abortedByClient = true;\s*controller\.abort\(\);/.test(src),
   'onAbort does not flag the cause');
ok('an already-aborted request is flagged too',
   /if \(request\.signal\.aborted\) \{ abortedByClient = true; controller\.abort\(\); \}/.test(src),
   'pre-aborted request not flagged');

// --- 2. a pre-dispatch disconnect takes the REFUND path --------------------
const i = src.indexOf('if (abortedByClient && !upstreamAccepted)');
ok('the disconnect branch is gated on the engine never responding',
   i > 0, 'branch missing');
const blk = src.slice(i, i + 1900);

ok('it only applies when the engine never accepted the job',
   /!upstreamAccepted/.test(blk), 'no upstreamAccepted guard');
ok('a collected payment is REFUNDED through the durable path',
   /recordRefund\(/.test(blk), 'no refund');
ok('the refund only happens for a collected payment',
   /if \(paymentSettled\)/.test(blk), 'refund not gated on paymentSettled');
ok('an uncollected authorization is RELEASED, not burned',
   /release-nonce/.test(blk), 'no release for an uncollected claim');
ok('a durable record is still written',
   /'abort:' \+ v\.nonce/.test(blk) && /status: refunded \? 'refunded' : 'refund_required'/.test(blk),
   'no durable abort record');
ok('the response is a distinct client_disconnected error, not gateway_timeout',
   /error: 'client_disconnected'/.test(blk), 'no distinct error id');
ok('it does not report a timeout label on this path',
   !/gateway_timeout/.test(blk), 'timeout label leaked into the disconnect path');

// --- 3. the TIMEOUT path is preserved and still does NOT auto-refund -------
const t = src.indexOf("'awaiting_reconciliation'");
ok('the timeout reconciliation record still exists', t > 0, 'timeout path removed');
// the response sits below the record, so widen the window
const tblk = src.slice(t - 1400, t + 1600);
ok('a timeout still reports gateway_timeout',
   /error: 'gateway_timeout'/.test(tblk), 'timeout response gone');
ok('a timeout still refuses to auto-refund (compute may still be billing)',
   !/recordRefund\(/.test(tblk), 'timeout path now auto-refunds');
ok('a timeout still records awaiting_reconciliation',
   /awaiting_reconciliation/.test(tblk), 'timeout record gone');

// --- 4. ordering: the disconnect check comes BEFORE the timeout handling ---
ok('the disconnect branch precedes the timeout handling',
   i > 0 && i < src.indexOf('awaiting_reconciliation'),
   'disconnect handled after the timeout path, so it is unreachable');

for (const f of fails) console.log('FAIL:', f);
console.log();
console.log(fails.length
  ? `R79-ABORT-DISCRIMINATION-FAIL (${fails.length})`
  : 'R79-ABORT-DISCRIMINATION-ALL-PASS (a client disconnect before the engine accepted '
    + 'is refunded/claimed, while our own timeout still records a reconciliation and '
    + 'never auto-refunds; the two abort causes are no longer conflated)');
process.exit(fails.length ? 1 : 0);