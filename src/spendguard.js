// LABEL: SpendGuard-Lite (R12) — six adapted guard rails + CPU cost estimator
// R12 AGENT A contract (FIXES_R12.md): sanitizeHeaders, rateLimit, preflightRunpodBalance,
// ceilingCheck, deficitCheck, wireDisconnectGuard + estimateBuildCostUsd helper.
// Config arrives ONLY via env.SG_* vars with hardcoded fallbacks (documented per check below):
//   SG_MIN_BALANCE     default "2.00" — RunPod account balance floor for the preflight gate (USD).
//   SG_MAX_JOB_COST    default "1.00" — per-request build-cost ceiling (USD); matches the max
//                      internal-tier price for a single file (10 GiB @ $0.10/GB = $1.00).
//   SG_CPU_RATE_PER_HR default "0.04" — CPU builder economics ($/hour); costs are CPU, NOT GPU.
// REJECTED source-doc patterns are deliberately ABSENT here: no HMAC/timestamp gates, no IP bans,
// no WAF/blocklist writes. wireDisconnectGuard only aborts the caller-supplied AbortController.
// Bindings used: env.SECURITY_KV and (R12.5 G2) env.CONSUMED_TX_STORE (both declared in
// wrangler.json). No new bindings invented.

const MAX_HEADERS = 25;      // header-count sanity ceiling
const MAX_KEY_BYTES = 64;    // max header NAME size
const MAX_VALUE_BYTES = 512; // max header VALUE size
const RATE_WINDOW_MS = 10000; // sliding window: 10s (contract-fixed)
const RATE_MAX_HITS = 10;     // max hits per window per IP (contract-fixed)
const RATE_KV_TTL = 60;       // NOTE: Cloudflare KV enforces expirationTtl >= 60s; the real 10s
                              // window is enforced by filtering stored timestamps, this TTL is GC.
const BALANCE_CACHE_KEY = "sg_rp_balance"; // cached RunPod balance (TTL 300s)
const BALANCE_TTL_S = 300;
const RUNPOD_GRAPHQL_URL = "https://api.runpod.io/graphql"; // balance query endpoint (account-level)

const _enc = new TextEncoder();
function byteLen(s) {
  return _enc.encode(String(s)).length;
}
function numEnv(rawVal, fallback) {
  const n = parseFloat(rawVal);
  return Number.isFinite(n) ? n : fallback;
}

// SAFETY: HEADER_SANITY_SANITIZER — malformed/oversized header floods never reach downstream logic.
// Reject: >25 headers, any name >64 bytes, any value >512 bytes. Returns {ok:true} | {ok:false,status:400}.
export async function sanitizeHeaders(request) {
  try {
    let count = 0;
    for (const [key, value] of request.headers.entries()) {
      count++;
      if (count > MAX_HEADERS) return { ok: false, status: 400 };
      if (byteLen(key) > MAX_KEY_BYTES || byteLen(value) > MAX_VALUE_BYTES) return { ok: false, status: 400 };
    }
    return { ok: true };
  } catch (e) {
    // Unreadable headers object -> cannot prove sanity -> fail closed.
    return { ok: false, status: 400 };
  }
}

// SAFETY: PER_IP_SLIDING_WINDOW_RATE_LIMIT — key `sg_rate:<ip>`, 10s window, max 10 hits,
// stored in env.SECURITY_KV as a JSON array of hit timestamps. Returns {ok:true} | {ok:false,status:429}.
// CALLER CARVE-OUT (K-B5 documentation, Kimi S3): this generic 512B value cap would
// false-reject real signed x402 payments (~600-900B PAYMENT-SIGNATURE). The gateway
// (src/index.js GATE 1b) hides payment headers from THIS pass and bounds them
// independently at 2048B before any downstream verification sees them.
// Future-dated timestamps are dropped too, so a poisoned record cannot extend anyone's window.
// On KV failure we fail CLOSED (R12.1 F6) with {ok:false,status:503} — an unverifiable rate state
// is treated as a configuration failure, never an availability pass-through.
// KNOWN LIMITATION (F11, Kimi K3 R4): KV get→put is a read-modify-write without locking — two
// concurrent same-IP requests can both read the pre-increment array and both pass before either
// put() lands, so a tight burst may slightly exceed RATE_MAX_HITS per window. Impact is bounded
// (each write still prunes to the sliding window and re-caps subsequent hits) and fail-closed on
// KV errors remains unchanged.
export async function rateLimit(env, ip) {
  // R12.1 F6: FAIL CLOSED on missing/failing KV — an unverifiable rate state is a 503, never a pass.
  if (!env || !env.SECURITY_KV) return { ok: false, status: 503, note: "kv_missing" };
  let hits = [];
  try {
    const key = "sg_rate:" + ip;
    const now = Date.now();
    const raw = await env.SECURITY_KV.get(key);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        // R12.5 G6: malformed state -> FAIL CLOSED. A record that parses but is not a timestamp
        // array is corrupted state just like unparseable JSON; silently resetting the window to []
        // would hand an attacker (or bit-rot) a free rate-limit reset.
        if (!Array.isArray(parsed)) return { ok: false, status: 503, note: "rate_state_corrupt" };
        hits = parsed.filter((t) => typeof t === "number");
      } catch (e) {
        // R12.5 G6: corrupt record -> FAIL CLOSED with 503 rate_state_corrupt. Never silently reset
        // the window: an unreadable rate state is treated like an unavailable one (R12.1 F6).
        return { ok: false, status: 503, note: "rate_state_corrupt" };
      }
    }
    hits = hits.filter((t) => t <= now && now - t < RATE_WINDOW_MS);
    if (hits.length >= RATE_MAX_HITS) return { ok: false, status: 429 };
    hits.push(now);
    await env.SECURITY_KV.put(key, JSON.stringify(hits), { expirationTtl: RATE_KV_TTL });
    return { ok: true };
  } catch (e) {
    return { ok: false, status: 503, note: "rate_state_unavailable" }; // FAIL CLOSED
  }
}

// SAFETY: RUNPOD_BALANCE_PREFLIGHT — cached account-balance gate so we NEVER take money we can't serve.
// GraphQL POST https://api.runpod.io/graphql body {"query":"query { myself { balance } }"} with
// Authorization: Bearer env.RUNPOD_API_KEY. Result cached in SECURITY_KV under `sg_rp_balance`
// (expirationTtl 300s) to keep the hot path off RunPod. Balance < SG_MIN_BALANCE -> {ok:false,status:503}.
// FAIL CLOSED: missing key, fetch error, non-numeric balance, or KV read failure on a cold cache all
// return {ok:false,status:503,note:"..."} — an unverifiable balance is treated as an unpayable one.
export async function preflightRunpodBalance(env) {
  // R12.1 F7: SECURITY_KV is required up front — without it neither the cache nor the daily
  // budget state can be maintained, so the gate fails CLOSED instead of degrading.
  if (!env || !env.SECURITY_KV) return { ok: false, status: 503, note: "kv_missing" };
  // R12.4 F25: validate the floor as finite AND non-negative — a malformed negative value
  // (e.g. "-1") would otherwise disable the balance floor entirely; fall back to default.
  let minBalance = numEnv(env.SG_MIN_BALANCE, 2.00);
  if (!Number.isFinite(minBalance) || minBalance < 0) minBalance = 2.00;
  // R12.8 K4: a stale cached balance must not mask MISSING credentials — validate the key
  // BEFORE trusting the cache (fail closed on absence).
  if (!env.RUNPOD_API_KEY) return { ok: false, status: 503, note: "runpod_key_missing" };
  let cachedRead;
  try {
    cachedRead = await env.SECURITY_KV.get(BALANCE_CACHE_KEY);
  } catch (e) {
    // R12.5 G12: a FAILED cache read is not a cache miss — fail closed (503), don't fall through.
    return { ok: false, status: 503, note: "balance_cache_unavailable" };
  }
  if (cachedRead !== null && cachedRead !== undefined) {
    const cachedBal = parseFloat(cachedRead);
    if (Number.isFinite(cachedBal)) {
      return cachedBal < minBalance ? { ok: false, status: 503, note: "low_balance" } : { ok: true };
    }
  }
  try {
    const res = await fetch(RUNPOD_GRAPHQL_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + env.RUNPOD_API_KEY
      },
      body: JSON.stringify({ query: "query { myself { balance } }" })
    });
    // R12.5 G13: require HTTP 2xx before trusting the body — a non-2xx with a parseable
    // balance-shaped body must never pass the preflight.
    if (!res.ok) return { ok: false, status: 503, note: "balance_http_" + res.status };
    const data = await res.json();
    const balance = data && data.data && data.data.myself ? data.data.myself.balance : undefined;
    if (typeof balance !== "number" || Number.isNaN(balance)) {
      return { ok: false, status: 503, note: "balance_unreadable" }; // FAIL CLOSED
    }
    try {
      await env.SECURITY_KV.put(BALANCE_CACHE_KEY, String(balance), { expirationTtl: BALANCE_TTL_S });
    } catch (e) { /* best-effort cache write; decision already made */ }
    return balance < minBalance ? { ok: false, status: 503, note: "low_balance" } : { ok: true };
  } catch (e) {
    return { ok: false, status: 503, note: "balance_fetch_failed" }; // FAIL CLOSED
  }
}

// SAFETY: PER_REQUEST_COST_CEILING — estimated build cost above SG_MAX_JOB_COST (default "1.00")
// is rejected before provisioning. Returns {ok:true} | {ok:false,status:400}.
// CEILING-TIER-ALIGN: the default matches the max internal-tier price for a single file
// (10 GiB @ $0.10/GB = $1.00) so every priceable internal-tier job can clear its own ceiling;
// the old 0.50 default let jobs between $0.50 and $1.00 receive a priced 402 challenge, then
// rejected them here AFTER payment.
export function ceilingCheck(costUsd, env) {
  // R13 FIX-A: guard a missing/non-object env (e.g. ceilingCheck(cost, undefined)) — without
  // this the SG_MAX_JOB_COST property read below THROWS instead of falling back to the
  // documented 1.00 default. Fail-closed preserved: numEnv(undefined, 1.00) applies the cap.
  if (!env || typeof env !== "object") env = {};
  const cap = numEnv(env.SG_MAX_JOB_COST, 1.00);
  const cost = Number(costUsd);
  // A cost we cannot even compute is unpriceable -> never provision it.
  // R12.1 F5: negative cost is malformed (would bypass the cap) -> reject, not pass.
  if (!Number.isFinite(cost) || cost < 0) return { ok: false, status: 400 };
  return cost > cap ? { ok: false, status: 400 } : { ok: true };
}

// SAFETY: SETTLEMENT_DEFICIT_AUDIT — CPU economics. paidMicroUsdc is the BigInt tier price that
// ACTUALLY settled on-chain and must cover buildCostUsd, else the request underpaid its compute
// -> {ok:false,status:402}. R13 FIX-B: the comparison happens in INTEGER micro-USDC units
// (BigInt on both sides) — converting the settlement to Number before /1e6 loses precision for
// settlements above 2^53 micro-USDC and could round an underpayment into a pass.
// Malformed inputs are treated as deficit (fail closed): we never let an unreadable settlement
// pass the audit.
export function deficitCheck(buildCostUsd, paidMicroUsdc) {
  try {
    const cost = Number(buildCostUsd);
    // R12.1 F5: negative cost would silently pass the audit -> treat as malformed (fail closed).
    if (!Number.isFinite(cost) || cost < 0) return { ok: false, status: 402 };
    // R13 FIX-B: integer micro-unit compare. cost*1e6 rounds to the nearest whole micro-USDC so
    // fractional-cent costs can never lower the required amount; any non-BigInt paid value fails
    // CLOSED (BigInt(Infinity) on an absurd cost throws -> caught below -> 402).
    if (typeof paidMicroUsdc !== "bigint") return { ok: false, status: 402 };
    const costMicro = BigInt(Math.round(cost * 1e6));
    return costMicro > paidMicroUsdc ? { ok: false, status: 402 } : { ok: true };
  } catch (e) {
    return { ok: false, status: 402 };
  }
}

// SAFETY: CLIENT_DISCONNECT_GUARD — wires request.signal abort -> controller.abort() so an abandoned
// client stops its own build. Explicitly NOT implemented (rejected source-doc patterns): NO IP ban,
// NO blocklist write, NO WAF push — disconnecting is not an offense, just cleanup.
// Returns {disconnectFlag, cleanup()}: disconnectFlag flips true when abort fires; cleanup()
// detaches the listener (call in BOTH success and catch paths so late aborts can't kill a live box).
export function wireDisconnectGuard(request, controller) {
  const state = { disconnectFlag: false };
  const onAbort = () => {
    state.disconnectFlag = true;
    try { controller.abort(); } catch (e) { /* controller already settled */ }
  };
  try {
    if (request && request.signal) {
      if (request.signal.aborted) onAbort();
      else request.signal.addEventListener("abort", onAbort, { once: true });
    }
  } catch (e) { /* no signal available -> guard stays inert */ }
  return {
    get disconnectFlag() { return state.disconnectFlag; },
    cleanup() {
      try {
        if (request && request.signal) request.signal.removeEventListener("abort", onAbort);
      } catch (e) { /* listener already gone */ }
    }
  };
}

// R12-ROUTEB: shared estimator for ceilingCheck(4)/deficitCheck(5) callers. CPU build economics
// (NOT GPU rates): cost = seconds * (SG_CPU_RATE_PER_HR / 3600), default rate $0.04/hr.
// Non-finite/negative execMs estimates to $0 flat overhead rather than throwing.
export function estimateBuildCostUsd(execMs, env) {
  if (!env || typeof env !== 'object') env = {}; // R25: fail-safe like ceilingCheck
  // R12.1 F5: validate the rate — non-finite/negative SG_CPU_RATE_PER_HR falls back to the
  // 0.04/hr default rather than producing a negative (cap-bypassing) cost.
  let ratePerHr = numEnv(env.SG_CPU_RATE_PER_HR, 0.04);
  // R12.8 K5: a ZERO (or negative/non-finite) rate disables every cost guard — treat as
  // misconfiguration and fall back to the documented default instead.
  if (!Number.isFinite(ratePerHr) || ratePerHr <= 0) ratePerHr = 0.04;
  // R12.5 G8: malformed/non-finite durations must NOT silently become $0 (that bypasses the
  // ceiling/deficit/budget guards). Return NaN so ceilingCheck/deficitCheck reject fail-closed.
  const n = Number(execMs);
  if (!Number.isFinite(n) || n < 0) return NaN;
  const secs = n / 1000;
  if (!Number.isFinite(secs)) return NaN;
  return Math.max(0, secs * (ratePerHr / 3600));
}

// R12.5 G10: daily-budget helpers moved to src/budget.js to keep spendguard.js
// to its exact seven-function contract.
