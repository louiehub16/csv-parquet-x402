// replay-store.js
// Strongly-consistent reservation store. Each Durable Object instance owns its storage partition;
// a single fixed id routes ALL reservations through one instance, so get+set is atomic w.r.t. requests.
//
// R9 (AGENT C): extended without regressing the existing /reserve tx reservation.
//   - POST /reserve       : on-chain tx reservation (R11-3: stores { transactionId }, idempotent retry 200 /
//                           replayed-under-different-id 409).
//   - POST /reserve-nonce : atomic nonce reservation (`nonce:<nonce>`); ANY existing nonce:<nonce> key
//                           is treated as USED -> 409 `already:'used'` forever (no TTL reuse, no overwrite).
//   - POST /own           : atomically persists the instance ownership mapping
//                           `instance_tx:<transactionId>` -> { txHash, owner }.
//   - GET  /owner         : returns the stored { txHash, owner } for ?transactionId=, else 404.
// Dispatch is by method + path so the reserve path keeps its exact prior behavior.
export class ConsumedTxStore {
  constructor(state, env) { this.state = state; }
  async fetch(request) {
    const url = new URL(request.url);
    const pathname = (url.pathname || "/").replace(/\/+$/, "") || "/";
    const method = (request.method || "GET").toUpperCase();

    // R63: atomic refund claim — the single-storage-partition get/put makes
    // "claim this refund" serializable, so two concurrent retries can never
    // both execute the same payout.
    if (method === "POST" && pathname === "/claim-refund") {
      const body = await this.readBody(request);
      if (!body || !body.nonce) return this.json({ ok: false, error: "invalid_json" }, 400);
      const key = "refund:" + String(body.nonce);
      const prior = await this.state.storage.get(key);
      if (prior) {
        const done = prior && prior.status === "refunded";
        return this.json({ ok: true, alreadyRefunded: !!done }, 200);
      }
      await this.state.storage.put(key, {
        nonce: String(body.nonce),
        payer: body.payer || null,
        amountUsdc: body.amountUsd != null ? body.amountUsd : (body.amountUsdc || 0),
        reason: body.reason || "unspecified",
        at: body.at || Date.now(),
        status: "claimed",
      });
      return this.json({ ok: true, claimed: true }, 200);
    }
    if (method === "POST" && pathname === "/mark-refunded") {
      const body = await this.readBody(request);
      if (!body || !body.nonce) return this.json({ ok: false, error: "invalid_json" }, 400);
      const key = "refund:" + String(body.nonce);
      const rec = (await this.state.storage.get(key)) || { nonce: String(body.nonce) };
      rec.status = "refunded";
      rec.refundedAt = Date.now();
      await this.state.storage.put(key, rec);
      return this.json({ ok: true, refunded: true }, 200);
    }
    if (method === "POST" && pathname === "/reserve-nonce") {
      return this.reserveNonce(request);
    }
    // R16: read-only nonce check for the verification-time replay gate.
    if (method === "POST" && pathname === "/check-nonce") {
      return this.checkNonce(request);
    }
    // R25: release a pre-dispatch nonce claim when upstream dispatch fails
    // (no compute bought) — so failed jobs don't burn valid nonces.
    // R34: finalize a VERIFIED+claimed nonce as permanently consumed.
    // Distinct from /reserve-nonce (which 409s on an existing key) so the
    // post-delivery burn is idempotent and cannot race itself.
    if (method === "POST" && pathname === "/finalize-nonce") {
      const body = await this.readBody(request);
      if (!body || body.nonce == null) return this.json({ ok: false, error: "invalid_json" }, 400);
      const key = "nonce:" + String(body.nonce);
      const rec = await this.state.storage.get(key);
      if (!rec) return this.json({ ok: false, error: "nonce_not_claimed" }, 409);
      rec.finalized = true;
      rec.finalizedAt = Date.now();
      await this.state.storage.put(key, rec);
      return this.json({ ok: true, finalized: true }, 200);
    }
    if (method === "POST" && pathname === "/release-nonce") {
      const body = await this.readBody(request);
      if (!body || body.nonce == null) return this.json({ ok: false, error: "invalid_json" }, 400);
      await this.state.storage.delete("nonce:" + String(body.nonce));
      return this.json({ ok: true, released: true }, 200);
    }
    // R12.5 G2: atomic daily-budget reservation + reset. A single fixed DO id routes ALL budget
    // operations through one storage partition, so read-modify-write is atomic across colos.
    if (method === "POST" && pathname === "/reserve-budget") {
      return this.reserveBudget(request);
    }
    if (method === "POST" && pathname === "/reset-budget") {
      return this.resetBudget(request);
    }
    // R12.5 G10: authoritative pre-payment budget read (GET /budget -> { ok, date, total }).
    if (method === "GET" && pathname === "/budget") {
      return this.getBudget();
    }
    if (method === "POST" && pathname === "/own") {
      return this.own(request);
    }
    if (method === "POST" && pathname === "/remove-owner") {
      return this.removeOwner(request);
    }
    if (method === "GET" && pathname === "/owner") {
      return this.getOwner(url);
    }
    // Default: existing /reserve on-chain tx reservation (kept intact).
    return this.reserve(request);
  }

  json(body, status) {
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }

  // Guard request.json() so a malformed/non-JSON body returns a clean 400 instead of an uncaught
  // parse error bubbling into a 500, and require the parsed body to be an object.
  async readBody(request) {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return null;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body;
  }

  // SAFETY: R7-1 + R11-3 — existing on-chain tx reservation.
  // R11-3: accepts { txHash, transactionId } and stores the value as `{ transactionId }` (not "1") so a
  // legitimate retry of the SAME logical request is idempotent:
  //   - same txHash + SAME transactionId     -> 200 {ok:true, idempotent:true} (caller proceeds to the
  //                                              idempotency lookup and gets the existing box URL).
  //   - same txHash + DIFFERENT transactionId -> 409 {ok:false, already:'consumed'} (a genuinely replayed
  //                                              single-use payment under a different id).
  // Atomicity preserved: single-partition get + put on one instance so consume decisions are serializable.
  async reserve(request) {
    const body = await this.readBody(request);
    if (!body) return this.json({ ok: false, error: "invalid_json" }, 400);
    const { txHash, transactionId } = body;
    if (!txHash) return this.json({ ok: false, error: "missing_tx" }, 400);
    const tid = transactionId == null ? "" : String(transactionId);
    const key = "consumed:" + String(txHash).toLowerCase();
    const existing = await this.state.storage.get(key);
    if (existing) {
      // R11-3: idempotent retry — same txHash + same transactionId -> legitimate, let the caller proceed.
      if (existing && typeof existing === "object" && existing.transactionId === tid) {
        return this.json({ ok: true, idempotent: true, tx: existing }, 200);
      }
      // Same txHash but a DIFFERENT (or legacy/missing) transactionId -> replayed single-use payment -> 409.
      return this.json({ ok: false, already: "consumed", tx: existing }, 409);
    }
    await this.state.storage.put(key, { transactionId: tid });
    return this.json({ ok: true, reserved: String(txHash).toLowerCase() }, 200);
  }

  // R9 + R10-3: atomic nonce reservation. Key `nonce:<nonce>`.
  // R10-3: ANY existing `nonce:<nonce>` key is treated as USED -> unqualified 409
  // (no TTL-based reuse, no overwrite of a used entry). A genuinely replayed nonce
  // must never succeed, so once written the key is rejected unconditionally.
  // R16: READ-ONLY used-nonce probe. Never writes; returns
  // { ok:true, used:true|false } so the verification gate can fail closed on
  // store unavailability without consuming anything. Consumption happens via
  // /reserve-nonce only after validated upstream success.
  async checkNonce(request) {
    const body = await this.readBody(request);
    if (!body || body.nonce == null) return this.json({ ok: false, error: "invalid_json" }, 400);
    const key = "nonce:" + String(body.nonce);
    const existing = await this.state.storage.get(key);
    return this.json({ ok: true, used: !!existing }, 200);
  }

  async reserveNonce(request) {
    const body = await this.readBody(request);
    if (!body || body.nonce == null) return this.json({ ok: false, error: "invalid_json" }, 400);
    const key = "nonce:" + String(body.nonce);
    const existing = await this.state.storage.get(key);
    if (existing) {
      return this.json({ ok: false, already: "used" }, 409);
    }
    // Persist permanently (no TTL). A nonce is single-use for the life of the store.
    await this.state.storage.put(key, { usedAt: Date.now() });
    return this.json({ ok: true }, 200);
  }

  // R9 + finding-2 (AGENT B): persist the instance ownership mapping atomically per transactionId.
  // Atomic: single-partition get/put on one instance. First read `instance_tx:<id>`; if an existing
  // record has a DIFFERENT txHash/owner, reject with 409 ALREADY_OWNED (do NOT overwrite). Only write
  // when absent or identical, so a concurrent/path-racing request can't clobber a prior owner's mapping.
  async own(request) {
    const body = await this.readBody(request);
    if (!body) return this.json({ ok: false, error: "invalid_json" }, 400);
    const { transactionId, txHash, owner } = body;
    if (!transactionId || !txHash || !owner) return this.json({ ok: false, error: "missing_fields" }, 400);
    const key = "instance_tx:" + transactionId;
    const existing = await this.state.storage.get(key);
    if (existing && typeof existing === "object") {
      const existingTxHash = existing.txHash == null ? null : String(existing.txHash);
      const existingOwner = existing.owner == null ? null : String(existing.owner);
      if (existingTxHash !== String(txHash) || existingOwner !== String(owner)) {
        return this.json({ ok: false, error: "ALREADY_OWNED", existing: { txHash: existingTxHash, owner: existingOwner } }, 409);
      }
      // Identical record already present -> idempotent success, do not overwrite.
      return this.json({ ok: true }, 200);
    }
    await this.state.storage.put(key, {
      txHash: String(txHash),
      owner: String(owner)
    });
    return this.json({ ok: true }, 200);
  }

  // R12.5 (AGENT B): remove the instance ownership mapping so the index sweep (AGENT A / A2) can
  // purge `instance_tx:<id>` from DO storage when a box expires. Deletes the key unconditionally and
  // returns 200 {ok:true} even when it is absent — idempotent sweep cleanup.
  async removeOwner(request) {
    const body = await this.readBody(request);
    if (!body) return this.json({ ok: false, error: "invalid_json" }, 400);
    const { transactionId } = body;
    if (!transactionId) return this.json({ ok: false, error: "missing_transaction" }, 400);
    await this.state.storage.delete("instance_tx:" + String(transactionId));
    return this.json({ ok: true }, 200);
  }

  // R9: read the stored ownership mapping for ?transactionId=. Returns { txHash, owner } or 404.
  async getOwner(url) {
    const transactionId = url.searchParams.get("transactionId");
    if (!transactionId) return this.json({ ok: false, error: "missing_transaction" }, 400);
    const stored = await this.state.storage.get("instance_tx:" + transactionId);
    if (!stored || typeof stored !== "object") {
      return this.json({ ok: false, error: "not_found" }, 404);
    }
    return this.json({ ok: true, txHash: stored.txHash, owner: stored.owner }, 200);
  }

  // R12.5 G2: atomic daily-budget reservation. Key `budget:daily` = { date, total }.
  // Single storage partition makes get+put atomic across all concurrent requests.
  // Auto-resets when the stored UTC date differs from today. Cap comes from the
  // request body (env-derived on the Worker side) so config lives in one place.
  async reserveBudget(request) {
    const body = await this.readBody(request);
    if (!body || typeof body.amountUsd !== "number" || !(body.amountUsd >= 0)) {
      return this.json({ ok: false, error: "invalid_amount" }, 400);
    }
    if (typeof body.capUsd !== "number" || !(body.capUsd >= 0)) {
      return this.json({ ok: false, error: "invalid_cap" }, 400);
    }
    // R12.7 I3 + R12.8 K1: IDEMPOTENCY by transactionId + KIND. The estimate and the actual-cost
    // reconciliation use DIFFERENT kinds (<tx>:estimate / <tx>:reconcile), so the reconcile delta
    // is never silently swallowed as an idempotent repeat. Same tx+kind repeated -> ok:true no-op.
    const kind = (typeof body.kind === "string" && body.kind) ? body.kind : "estimate";
    const txKey = body.transactionId ? `budget_tx:${String(body.transactionId)}:${kind}` : null;
    if (txKey) {
      const prior = await this.state.storage.get(txKey);
      if (prior && typeof prior === "object" && typeof prior.amountUsd === "number") {
        return this.json({ ok: true, newTotal: prior.totalAfter, idempotent: true }, 200);
      }
    }
    const key = "budget:daily";
    const today = new Date().toISOString().slice(0, 10); // UTC date
    let rec = await this.state.storage.get(key);
    if (rec !== undefined && rec !== null) {
      // R12.5 G3-followup: a PRESENT but malformed/negative record is corrupted state — fail CLOSED
      // (503) rather than silently reopening the budget. Only a genuinely absent record, or one from
      // a prior UTC date, resets to zero.
      const badShape = typeof rec !== "object" || Array.isArray(rec) || typeof rec.total !== "number" ||
                       !Number.isFinite(rec.total) || rec.total < 0;
      if (badShape) return this.json({ ok: false, error: "budget_state_corrupt" }, 503);
      if (rec.date === today) {
        const projected = Number(rec.total) + Number(body.amountUsd);
        if (!(projected < body.capUsd)) {
          // Cap enforcement — reject BEFORE incrementing; nothing is reserved.
          return this.json({ ok: false, already: "daily_cap_reached", total: rec.total, cap: body.capUsd }, 503);
        }
        await this.state.storage.put(key, { date: today, total: projected });
        // R12.7 J1: record the tx reservation in EVERY successful branch (not just fresh-day) so
        // retries stay idempotent regardless of which path first reserves.
        if (txKey) {
          await this.state.storage.put(txKey, { amountUsd: Number(body.amountUsd), totalAfter: projected });
        }
        return this.json({ ok: true, newTotal: projected }, 200);
      }
    }
    // Fresh day (absent record or prior-date record) -> reset baseline, then reserve.
    const projected = Number(body.amountUsd);
    if (!(projected < body.capUsd)) {
      return this.json({ ok: false, already: "daily_cap_reached", total: 0, cap: body.capUsd }, 503);
    }
    await this.state.storage.put(key, { date: today, total: projected });
    if (txKey) {
      await this.state.storage.put(txKey, { amountUsd: Number(body.amountUsd), totalAfter: projected });
    }
    return this.json({ ok: true, newTotal: projected }, 200);
  }

  // R12.5 G2 + R12.7 J2/K2: midnight reset zeroes budget:daily AND purges ALL stale
  // budget_tx:<transactionId>[:kind] idempotency records. DO storage.list() returns a MAP and
  // paginates via startAfter (NOT cursor/list_complete) - re-list after each delete batch until empty.
  async resetBudget(request) {
    await this.state.storage.delete("budget:daily");
    let purgedTx = 0;
    let startAfter;
    while (true) {
      const page = await this.state.storage.list({ prefix: "budget_tx:", limit: 1000, ...(startAfter ? { startAfter } : {}) });
      const keys = [...page.keys()];
      if (!keys.length) break;
      await this.state.storage.delete(keys);
      purgedTx += keys.length;
      startAfter = keys[keys.length - 1];
    }
    return this.json({ ok: true, purgedTx }, 200);
  }
  // R12.5 G10: authoritative budget read for the pre-payment gate.
  // A malformed stored record fails closed (503) — same policy as reserveBudget.
  async getBudget() {
    const key = "budget:daily";
    const today = new Date().toISOString().slice(0, 10);
    const rec = await this.state.storage.get(key);
    if (rec === undefined || rec === null) return this.json({ ok: true, date: today, total: 0 }, 200);
    if (typeof rec !== "object" || Array.isArray(rec) || typeof rec.total !== "number" ||
        !Number.isFinite(rec.total) || rec.total < 0) {
      return this.json({ ok: false, error: "budget_state_corrupt" }, 503);
    }
    // Prior-date record: stale until the next reservation resets it; report as-is (0-effective).
    if (rec.date !== today) return this.json({ ok: true, date: rec.date, total: rec.total }, 200);
    return this.json({ ok: true, date: today, total: rec.total }, 200);
  }
}