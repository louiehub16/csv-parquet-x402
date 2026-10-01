// R38 regression test: a refund is only "complete" once the DO ACKNOWLEDGES it.
//
// BUG: after a successful payout the gateway wrote the KV mirror and POSTed
// /mark-refunded to the Durable Object, but never inspected that response. A DO
// 5xx or a thrown fetch still returned true, so the caller reported
// refund:'completed' while NO durable record existed anywhere -- and because the
// claim was considered done, no operator sweep could ever retry it. Collected
// funds became permanently unrecoverable through an invisible failure.
//
// Contract:
//   DO acks {ok:true}            -> refund reported complete
//   DO errors / {ok:false}       -> NOT complete; claim left retryable
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- the acknowledgment must actually be checked ---
const i = idx.indexOf("https://internal/mark-refunded");
ok('mark-refunded call located', i > 0, 'not found');
const win = idx.slice(Math.max(0, i - 1400), i + 1600);

ok('the DO response status is checked', /mRes\s*&&\s*mRes\.ok/.test(win), 'no res.ok check');
ok('the DO payload ok flag is required', /mData\s*&&\s*mData\.ok\s*===\s*true/.test(win),
   'no ok:true requirement');
ok('a non-acknowledged mark leaves the refund retryable',
   /if\s*\(!markOk\)/.test(win) && /return false;/.test(win.slice(win.indexOf('if (!markOk)'))),
   'unacknowledged mark still reports success');
ok('the record is not marked refunded before acknowledgement',
   /record\.status\s*=\s*'payout_sent_unconfirmed'/.test(win), 'no unconfirmed status');
ok('success is returned only after markOk', /return true;/.test(win), 'no success return');

// Ordering: the 'refunded' status must come AFTER the guard, never before it.
{
  const guardAt = win.indexOf('if (!markOk)');
  const refundedAt = win.indexOf("record.status = 'refunded'");
  ok("'refunded' is written only after the guard passes",
     guardAt > 0 && refundedAt > guardAt, `guard@${guardAt} refunded@${refundedAt}`);
}

// --- the DO must actually answer with ok:true on success ---
{
  const store = readFileSync(new URL('./replay-store.js', import.meta.url), 'utf8');
  ok('DO /mark-refunded returns ok:true on success',
     /this\.json\(\{\s*ok:\s*true,\s*refunded:\s*true\s*\},\s*200\)/.test(store),
     'DO does not acknowledge success');
  ok('DO /mark-refunded rejects a malformed body',
     /invalid_json/.test(store), 'no validation');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R38-MARK-ACK-FAIL (${fails.length})`
  : 'R38-MARK-ACK-ALL-PASS (refund is reported complete only after the DO acknowledges ' +
    'ok:true; an unacknowledged mark stays retryable and the record is not marked refunded)');
process.exit(fails.length ? 1 : 0);
