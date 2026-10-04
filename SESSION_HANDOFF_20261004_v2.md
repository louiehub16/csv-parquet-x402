# SESSION_HANDOFF — csv-parquet-x402 — v2 (2026-10-04)

Supersedes `SESSION_HANDOFF_20260930_v1.md`.

## 1. Overall goal

An x402 v2 paid API selling CSV/TSV/TXT → Apache Parquet conversion, priced in
micro-USDC on Base (chainId 8453), settled through the Coinbase CDP facilitator.
Cloudflare Worker gateway (`src/index.js`) + Python RunPod engine
(`worker/main.py`). Under an ongoing dual-model review loop; the bar is **BOTH
pinned `stealth/space-bunny-alpha` seats returning PASS on ONE unchanged tree.**

## 2. VERIFIED CURRENT STATE

**DUAL PASS achieved at round R83** (commit `b0d8ba4` + uncommitted working tree).

| Evidence | Result |
|---|---|
| `bunnyA` (security seat) | **PASS**, `finish_reason: stop`, 47 content chars |
| `bunnyB` (code seat) | **PASS**, `finish_reason: stop`, 47 content chars |
| `python review/make_manifest.py review/r83 --check` | `source_drift: []` |
| `python _gate.py` | **42/42 suites green** |
| `NO_VERDICT` markers | none — both are real verdicts, not transport drops |

No commit was made and nothing was deployed. All work is in the working tree.

### Uncommitted changes (the R81 + R82 fix set)

| File | Change |
|---|---|
| `src/spendguard.js` | `rateLimit(env, ip, opts={})` is **read-only by default**; the mutating count is opt-in via `opts.count` |
| `src/index.js` | pre-verification rate check stays read-only; `{count:true}` is used only **inside `settle()`**, after `verifyPayment` proved the authorization |
| `src/mint_vector.mjs` | **was stale** — fixed to emit the required `accepted` object, `maxTimeoutSeconds:600`, a 555s window, the real merchant, and a `merchant` field |
| `src/integration_test.mjs`, `src/timeout_durability_test.mjs` | settlement-receipt topics now derive the payer from `vec.payer_expected` instead of a hardcoded address |
| `src/budget_order_test.mjs` | replaced a hardcoded 2600-char slice with brace-balanced callback matching |
| `src/e2e_vector.json` | re-minted (a fixture; its payer/nonce/window change by design) |

New untracked helpers: `_gate.py` (canonical gate), `_ctl_budget_order.py`,
`_ctl_receipt_fixture.py` (negative controls).

## 3. THE THREE REAL BUGS FOUND IN THIS SESSION

1. **R81 (carried in, fixed here):** `rateLimit()` wrote a timestamp to KV on every
   request, including ones with no valid payment. An unauthenticated caller could
   flood until the shared per-IP window was full and lock out every legitimate
   client behind that address — free DoS against paying customers. Covered by
   `src/rate_limit_scope_test.mjs`; negative control reverts the fix and confirms RED.

2. **`mint_vector.mjs` produced non-conformant vectors.** It omitted the required v2
   `accepted` object, used a 3660s authorization window against the gateway's own
   600s bound, and paid a merchant address that is not the one in `wrangler.jsonc` /
   `public/.well-known/x402.json`. Every re-mint therefore produced a vector the
   gateway correctly refused. This is what made 9 suites fail when the vector aged
   out — a **fixture** bug, not a product defect. The Python twin `mint_vector.py`
   always had the correct shape; the `.mjs` twin had drifted.

3. **Settlement-receipt fixtures hardcoded an old payer.** `e2e_vector.json` is
   re-minted with a fresh throwaway key, so the `AuthorizationUsed`/`Transfer`
   topics never matched the live payer and the on-chain proof could not bind —
   502 `settlement_unconfirmed` for a correct payment.

## 4. FINDINGS ADJUDICATED AS NOT-A-DEFECT (do not re-litigate)

Full evidence in `review/r82/adjudication.json` + `review/r83/common.txt`.

- **A — "verifyPayment does not validate `accepted.extra`".** Real as a literal, but
  **not** a money-loss path. `twaDigest` (`x402.js:248`) covers only
  `{from,to,value,validAfter,validBefore,nonce}` + the domain separator; `extra` is
  not in the EIP-712 typed data, so the payer never signs it and the facilitator never
  acts on it. Measured: five `extra` variants all reach an identical settlement
  boundary, while every economic field (asset/payTo/amount/network/
  maxTimeoutSeconds/scheme) is refused by its own specific gate. The **proposed fix
  was also rejected** — requiring exact `extra` equality would reject otherwise-valid
  conforming clients, an interop regression rather than a hardening.
- **B — "nonce is finalized before upstream conversion succeeds".** Incorrect:
  `consumeNonce()` (`index.js:801-806`) is the **atomic pre-dispatch DO claim**, not a
  finalize. It is released only on `definitelyNotSubmitted`; otherwise it stays
  claimed and refundable. Deferring it as proposed would **reopen the double-spend
  window** the claim exists to close.

## 5. HOW TO RUN THE GATE AND THE NEXT ROUND

```bash
cd "/c/Users/John Doe/Desktop/csv-parquet-x402"

# full gate (re-mints the vector first so it cannot expire mid-run)
python _gate.py                      # -> 42/42 green, GATE ALL-GREEN

# negative controls (each must print CONTROL VALID)
python _ctl_budget_order.py
python _ctl_receipt_fixture.py

# a review round: FRESH dir only, NEVER `cp -r` an old one
rm -rf review/r84 && mkdir -p review/r84
cp review/r83/common.txt review/r84/common.txt     # then append this round's fixes
python review/make_manifest.py review/r84          # freeze the tree
python review_harness.py bunnyA security --out review/r84   # seat 1
python review_harness.py bunnyB code     --out review/r84   # seat 2 (SEQUENTIAL)
python review/make_manifest.py review/r84 --check  # MUST be source_drift: []
```

Round dirs are disposable: `run_reviews.py` is created per round and deleted. The
protocol lives in `review_harness.py` (`<seat> <config> --out <dir>`).

## 6. WATCH-OUTS (each one cost real time)

- **`src/e2e_vector.json` is re-minted** with a fresh throwaway key, so its payer,
  nonce and window change on every run. Read it **inside** the test body, never at
  import time, and never hardcode its payer. This is the documented
  `time_window_violation` trap.
- **7 of the 8 `worker/test_*.py` are STANDALONE scripts** that assert at import and
  end in `sys.exit`. Running them under pytest produces `INTERNALERROR`. Only
  `worker/test_engine.py` is a real pytest module. `_gate.py` probes for this.
- **`node mint_vector.mjs` must produce the `accepted` object.** If a suite fails
  with `missing_accepts` / `malformed_requirements`, suspect the fixture first.
- **Two suites still hardcode `0x19e7e376…`** (`gw_smoke.mjs`,
  `result_auth_depth_test.mjs`) and currently pass — do **not** "fix" them blindly.
- **Disk C: is at ~98% (1.3 GB free).** No heavy local build. Build the engine image
  in CI.
- `core.autocrlf=true`, no `.gitattributes`: the repo stores LF. A checkout can write
  CRLF, which the byte-hash manifest correctly reports as `source_drift` with zero
  textual diff. Normalise to LF if that happens.
- Edit multi-line JS via a disposable `_edit.py` with `assert data.count(anchor)==1`;
  **CRLF defeats exact-string matches** — prefer line-index edits.
- On Windows use `python`, not `python3`; `cd` and use relative filenames for
  `node --check`.

## 7. PRE-LAUNCH (unchanged, still open)

`REVIEW_LEDGER.md` §6 is authoritative: KV namespace id, R2 bucket + `RESULTS`
binding, the 9 Worker secrets, the `ConsumedTxStore` DO migration, engine image
built **in CI** with a pinned digest, a funded `MERCHANT_WALLET_ADDRESS`, and the
RunPod `cpu5c` endpoint with **every** env var set (an endpoint with empty `env` still
reports `ready:1`). Finish with one real self-paid conversion — per `MARKETS.md` that
single settled payment is the indexing event.

Note the ledger's standing warning: **6 of 59 rounds were genuine dual passes and five
of those were followed by further defects.** A single dual pass is not convergence.