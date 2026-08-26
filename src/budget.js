// LABEL: Daily-budget helpers (R12.5 G10) — split from spendguard.js so SpendGuard keeps its
// exact seven-function contract. All budget enforcement truth lives in the CONSUMED_TX_STORE
// Durable Object (single storage partition => atomic across colos).

// Reserve `amountUsd` against today's running total. FAIL CLOSED on any error/unavailability.
export async function reserveDailyBudget(env, amountUsd, transactionId) {
  if (!env || !env.CONSUMED_TX_STORE) return { ok: false, status: 503, note: "do_missing" }; // FAIL CLOSED
  const amt = Number(amountUsd);
  if (!Number.isFinite(amt) || amt < 0) return { ok: false, status: 503, note: "invalid_amount" };
  // Cap derived from the SAME SG_DAILY_BUDGET_USD env (default 50, validated finite non-negative)
  // so the DO cap always matches the Worker's early-gate cap.
  const capRaw = parseFloat(env.SG_DAILY_BUDGET_USD || "50");
  const capUsd = (Number.isFinite(capRaw) && capRaw >= 0) ? capRaw : 50;
  const id = env.CONSUMED_TX_STORE.idFromName("singleton");
  const stub = env.CONSUMED_TX_STORE.get(id);
  const resp = await stub.fetch("https://internal/reserve-budget", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amountUsd: amt, capUsd, transactionId: transactionId || null })
  }).catch(() => null);
  // R12.6 H5 (fixed per Fable5): null-check resp FIRST — calling .json() on a null response
  // throws a synchronous TypeError that escapes the documented fail-closed contract. Then parse
  // once, and read the body even on non-2xx so a genuine DO cap rejection (503 daily_cap_reached)
  // is distinguishable from DO unavailability.
  if (!resp) return { ok: false, status: 503, note: "budget_state_unavailable" }; // FAIL CLOSED
  const data = await resp.json().catch(() => null);
  if (!resp.ok) {
    if (data && data.already === "daily_cap_reached") {
      return { ok: false, status: 503, note: "daily_cap_reached" };
    }
    return { ok: false, status: 503, note: "budget_state_unavailable" }; // FAIL CLOSED
  }
  if (!data || data.ok !== true) {
    // Explicit rejection (e.g. cap exceeded in the DO). Honor the DO's status when it sent one.
    const st = data && typeof data.status === "number" ? data.status : 503;
    return { ok: false, status: st, note: "budget_reserve_rejected" };
  }
  return { ok: true, newTotal: data.newTotal };
}

// Midnight cron: zero the DO-side daily counter. Failures propagate to the caller (G5) so
// Cloudflare retries the cron invocation.
// R12.6 H4: return { ok: true } on success — index.js scheduled() checks .ok, and an undefined
// return would make a SUCCESSFUL reset throw and permanently fail the daily cron.
export async function resetDailyBudget(env) {
  if (!env || !env.CONSUMED_TX_STORE) throw new Error("resetDailyBudget: CONSUMED_TX_STORE missing");
  const id = env.CONSUMED_TX_STORE.idFromName("singleton");
  const stub = env.CONSUMED_TX_STORE.get(id);
  const resp = await stub.fetch("https://internal/reset-budget", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  }).catch(() => null);
  if (!resp || !resp.ok) throw new Error("resetDailyBudget: DO reset failed");
  return { ok: true };
}


// R17: READ-ONLY budget probe via the store's NATIVE GET /budget endpoint
// ({ ok, date, total }). Never writes; fail-closed on unavailability/malformation.
export async function getDailyBudget(env) {
  if (!env || !env.CONSUMED_TX_STORE) return { ok: false, status: 503, note: "do_missing" };
  const capRaw = parseFloat(env.SG_DAILY_BUDGET_USD || "50");
  const capUsd = (Number.isFinite(capRaw) && capRaw >= 0) ? capRaw : 50;
  const id = env.CONSUMED_TX_STORE.idFromName("singleton");
  const stub = env.CONSUMED_TX_STORE.get(id);
  const resp = await stub.fetch("https://internal/budget", {
    method: "GET",
  }).catch(() => null);
  if (!resp) return { ok: false, status: 503, note: "budget_state_unavailable" };
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data || data.ok !== true)
    return { ok: false, status: 503, note: "budget_state_unavailable" };
  const today = new Date().toISOString().slice(0, 10);
  // Only today's total counts toward the cap; a prior date's residual is spent.
  const spentUsd = data.date === today ? (typeof data.total === "number" ? data.total : 0) : 0;
  if (typeof data.total !== "number") return { ok: false, status: 503, note: "budget_state_malformed" };
  return { ok: true, spentUsd, capUsd };
}

// R24: reconcile a reservation after the fact — pass the ACTUAL cost (0 if no
// compute ran, e.g. upstream unreachable before dispatch). Uses the DO's
// reconcile kind so it adjusts rather than double-counts.
export async function reconcileDailyBudget(env, transactionId, actualUsd) {
  if (!env || !env.CONSUMED_TX_STORE) return { ok: false, status: 503, note: "do_missing" };
  const amt = Number(actualUsd);
  if (!Number.isFinite(amt) || amt < 0) return { ok: false, status: 503, note: "invalid_amount" };
  const capRaw = parseFloat(env.SG_DAILY_BUDGET_USD || "50");
  const capUsd = (Number.isFinite(capRaw) && capRaw >= 0) ? capRaw : 50;
  const id = env.CONSUMED_TX_STORE.idFromName("singleton");
  const stub = env.CONSUMED_TX_STORE.get(id);
  const resp = await stub.fetch("https://internal/reserve-budget", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ amountUsd: amt, capUsd, transactionId, kind: "reconcile" })
  }).catch(() => null);
  if (!resp) return { ok: false, status: 503, note: "budget_state_unavailable" };
  const data = await resp.json().catch(() => null);
  if (!resp.ok || !data || data.ok !== true)
    return { ok: false, status: 503, note: "budget_reconcile_rejected" };
  return { ok: true, newTotal: data.newTotal };
}
