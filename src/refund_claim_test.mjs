// R19 regression test: refund-claim ownership + payout arbitration.
//
// Two money-critical bugs closed here:
//   R18-introduced: the gateway used a STABLE claimant token, so after a failed
//     payout its OWN retry saw its own live claim, was refused, and the payer's
//     settled funds were never refunded.  Fixed with a per-ATTEMPT token.
//   R19: a claim nobody finished could never be taken over -> stranded funds.
//
// Asserts OUTCOMES, not source substrings:
//   1. first claim            -> claimed:true
//   2. concurrent duplicate   -> claimed:false   (cannot double-pay)
//   3. same attempt resumes   -> claimed:true    (retry after failed payout)
//   4. dead claim + new token -> claimed:true    (takeover; funds not stranded)
//   5. completed payout       -> alreadyRefunded:true, nobody re-executes
import { ConsumedTxStore } from './replay-store.js';

const NONCE = 'a'.repeat(64);
const BASE = {
  nonce: NONCE, payer: '0xpayer', amountUsdc: 10000, reason: 'upstream_error',
};

// Minimal in-memory Durable-Object storage.
//
// R42: models `storage.transaction(cb)` with REAL semantics -- a serialized
// critical section over the same map, with rollback on throw. A plain get/put
// pair is NOT atomic in a real Durable Object (the input gate allows an
// interleaving between two awaits), which is exactly the bug R42 fixes, so the
// fake must not accidentally make the old code look correct.
class FakeStorage {
  constructor() { this.map = new Map(); this._chain = Promise.resolve(); }
  async get(k) { return this.map.get(k); }
  async put(k, v) { this.map.set(k, v); }
  async delete(k) { this.map.delete(k); }
  transaction(cb) {
    // Serialize transactions and roll back if the callback throws, matching
    // the real API's all-or-nothing guarantee.
    const run = this._chain.then(async () => {
      const backup = new Map(this.map);
      try {
        return await cb(this);
      } catch (e) {
        this.map.clear();
        for (const [k, v] of backup) this.map.set(k, v);
        throw e;
      }
    });
    this._chain = run.then(() => undefined, () => undefined);
    return run;
  }
}

async function claim(store, payload) {
  const inst = new ConsumedTxStore({ storage: store }, {});
  const req = new Request('https://internal/claim-refund', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const res = await inst.fetch(req);
  return await res.json();
}

const fails = [];
function expect(label, cond, got) {
  if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`);
}

const store = new FakeStorage();
const key = 'refund:' + NONCE;

// 1. First claim succeeds.
const r1 = await claim(store, { ...BASE, claimant: 'gw:A' });
expect('first claim must be claimed:true', r1.claimed === true, r1);

// 2. A CONCURRENT different attempt must not be allowed to execute.
const r2 = await claim(store, { ...BASE, claimant: 'gw:B' });
expect('concurrent duplicate must be claimed:false', r2.claimed === false, r2);

// 3. The SAME attempt resumes after a failed payout (the R18 deadlock).
const r3 = await claim(store, { ...BASE, claimant: 'gw:A' });
expect('same-attempt retry must resume', r3.claimed === true, r3);

// 4. A DEAD claim (past the stale window) is taken over — funds not stranded.
store.map.set(key, { ...store.map.get(key), at: 0 });
const r4 = await claim(store, { ...BASE, claimant: 'gw:C' });
expect('stale claim must be taken over', r4.claimed === true, r4);
expect('ownership must rotate to gw:C', store.map.get(key).claimant === 'gw:C',
  store.map.get(key));

// 5. Once completed, nobody may re-execute the payout.
store.map.set(key, { ...store.map.get(key), status: 'refunded' });
const r5 = await claim(store, { ...BASE, claimant: 'gw:D' });
expect('completed refund must report alreadyRefunded:true', r5.alreadyRefunded === true, r5);
expect('completed refund must NOT be re-claimed', r5.claimed !== true, r5);

for (const f of fails) console.log('FAIL:', f);
if (!fails.length) {
  console.log('REFUND-CLAIM-ALL-PASS (claim, concurrent-refusal, same-attempt-resume, ' +
              'stale-takeover, no-re-execute)');
}
process.exit(fails.length ? 1 : 0);
