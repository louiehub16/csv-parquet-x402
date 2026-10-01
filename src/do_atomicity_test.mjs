// R42 regression test: refund claims and nonce reservations must be ATOMIC.
//
// BUG: the Durable Object read a key, awaited, then wrote it. A DO serializes
// EVENTS and keeps at most one request in flight, but it does NOT make
// get-then-await-then-put atomic -- two concurrent requests can both observe
// absence, both decide to proceed, and both succeed. For /claim-refund that is a
// DOUBLE REFUND; for /reserve-nonce it is a REPLAY of a single-use
// authorization. The file's own header comment asserted the opposite.
//
// This fires N concurrent requests at ONE nonce and asserts exactly one wins.
import { ConsumedTxStore } from './replay-store.js';

const N = 'a'.repeat(64);
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// A Durable-Object-like storage: get/put are individually atomic, but a bare
// get-then-put is NOT -- the interleaving below is what the real runtime allows.
class FakeStorage {
  constructor() {
    this.map = new Map();
    this._chain = Promise.resolve();
    this.inTransaction = false;
  }
  async get(k) { return this.map.get(k); }
  async put(k, v) { this.map.set(k, v); }
  async delete(k) { this.map.delete(k); }
  // Real transaction(): a serialized critical section, all-or-nothing.
  transaction(cb) {
    const run = this._chain.then(async () => {
      const backup = new Map(this.map);
      this.inTransaction = true;
      try {
        return await cb(this);
      } catch (e) {
        this.map.clear();
        for (const [k, v] of backup) this.map.set(k, v);
        throw e;
      } finally {
        this.inTransaction = false;
      }
    });
    this._chain = run.then(() => undefined, () => undefined);
    return run;
  }
}

async function call(store, path, body) {
  const inst = new ConsumedTxStore({ storage: store }, {});
  const res = await inst.fetch(new Request('https://internal' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }));
  return { status: res.status, body: await res.json() };
}

// ---------- 1. concurrent /claim-refund: exactly one claimant ----------
{
  const store = new FakeStorage();
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      call(store, '/claim-refund', {
        nonce: N, payer: '0xpayer', amountUsdc: 10000,
        reason: 'upstream_error', claimant: 'gw:' + i, at: Date.now(),
      })),
  );
  const claimed = results.filter((r) => r.body.claimed === true);
  const held = results.filter((r) => r.body.claimed === false);
  console.log('claim-refund  ->', JSON.stringify({
    total: results.length, claimed: claimed.length, held: held.length,
    statuses: [...new Set(results.map((r) => r.status))],
  }));

  ok('exactly one claimant wins', claimed.length === 1,
     `${claimed.length} of ${results.length} claimed`);
  ok('every other caller is refused (claimed:false)', held.length === results.length - 1,
     `${held.length} refused`);
  ok('refusals name the owning claimant',
     held.every((r) => !!r.body.claimedBy), held.map((r) => r.body.claimedBy));
  ok('all responses are ok:true (no 5xx)', results.every((r) => r.status === 200),
     [...new Set(results.map((r) => r.status))]);
}

// ---------- 2. concurrent /reserve-nonce: exactly one reservation ----------
{
  const store = new FakeStorage();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => call(store, '/reserve-nonce', { nonce: N })),
  );
  const okCount = results.filter((r) => r.body.ok === true).length;
  const used = results.filter((r) => r.body.already === 'used').length;
  console.log('reserve-nonce ->', JSON.stringify({
    total: results.length, reserved: okCount, rejectedAsUsed: used,
  }));

  ok('exactly one nonce reservation wins', okCount === 1, `${okCount} of ${results.length}`);
  ok('the rest are rejected as already used', used === results.length - 1,
     `${used} rejected`);
  ok('rejections carry HTTP 409', results.filter((r) => r.status === 409).length === results.length - 1,
     [...new Set(results.map((r) => r.status))]);
}

// ---------- 3. the source must use storage.transaction for these decisions ----------
{
  const src = (await import('node:fs')).readFileSync(
    new URL('./replay-store.js', import.meta.url), 'utf8');

  const claimStart = src.indexOf('pathname === "/claim-refund"');
  const claimEnd = src.indexOf('pathname === "/mark-refunded"');
  const claimBody = src.slice(claimStart, claimEnd);
  ok('/claim-refund decides inside storage.transaction',
     /storage\.transaction\(/.test(claimBody), 'no transaction');
  ok('/claim-refund writes through the transaction handle, not this.state',
     /txn\.put\(/.test(claimBody) && !/this\.state\.storage\.put\(/.test(claimBody),
     'writes outside the transaction');

  const rnStart = src.indexOf('async reserveNonce(');
  const rnEnd = src.indexOf('// R9 + finding-2', rnStart);
  const rnBody = src.slice(rnStart, rnEnd);
  ok('/reserve-nonce decides inside storage.transaction',
     /storage\.transaction\(/.test(rnBody), 'no transaction');
  ok('/reserve-nonce writes through the transaction handle',
     /txn\.put\(/.test(rnBody), 'writes outside the transaction');

  ok('the header no longer claims get+set is atomic w.r.t. requests',
     !/so get\+set is atomic w\.r\.t\. requests/.test(src),
     'the incorrect atomicity claim is still in the header');
  ok('the atomicity rationale is documented',
     /does NOT make a get-then-await-then-put/.test(src), 'rationale missing');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R42-ATOMICITY-FAIL (${fails.length})`
  : 'R42-ATOMICITY-ALL-PASS (8 concurrent claims -> 1 winner; 8 concurrent nonce ' +
    'reservations -> 1 winner; both decide and write inside storage.transaction)');
process.exit(fails.length ? 1 : 0);
