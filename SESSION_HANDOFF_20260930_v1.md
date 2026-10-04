# SESSION HANDOFF — csv-parquet-x402 (v1, 2026-09-30 23:05)

Self-contained. A zero-context session can resume from this file alone.

## 1. What this project is

`C:\Users\John Doe\Desktop\csv-parquet-x402` — an **x402 v2 paid API** that sells
CSV/TSV/TXT → Apache Parquet conversion.

- **Seller:** Cloudflare Worker gateway, `src/index.js` (name `csv-parquet-compressor`).
- **Engine:** Python RunPod worker, `worker/main.py` + `worker/Dockerfile`.
- **Settlement:** Coinbase CDP facilitator (`src/cdp.js`) — USDC on Base, chainId 8453.
- **SpendGuard:** installed from `docker-on-tap`, R12.5-hardened. Modules:
  `src/spendguard.js`, `src/budget.js`, `src/replay-store.js`.
- **Discovery:** `public/llms.txt`, `public/.well-known/x402.json`, `public/openapi.json`,
  `public/mcp/config` (shipped via the `assets` binding). Runbook: `MARKETS.md`.

**Not deployed.** See §5.

## 2. Last genuine user instructions (recovered from the transcript)

| When | Message | Effect |
|---|---|---|
| Aug 23 session start | "…need to build this… will post to all known x402 markets, use all posting and auto discovery methods… and also install the SpendGuard method too." | Build + market-posting + SpendGuard |
| Aug 23 22:41 | `go` | Authorize continuing the fix→review loop |
| Aug 23 22:43 | `are you there? **confirm only**` | **Confirm scope, change nothing** |

> The `C:\Hermes Data\…_20260823_193907_494116.txt` archive **stops at `go`** — it is stale.
> The session was actually **live until today 22:48**. Disk + the session DB are authoritative;
> the archive is not. This is the "handoff says done" trap from the handoff skill.

## 3. VERIFIED CURRENT STATE (all re-measured 2026-09-30 23:0x)

### Test gate — 5/5 GREEN (re-run just now, not quoted from a summary)

```
selftest           SELFTEST-ALL-PASS
e2e_test           E2E-ALL-PASS
gw_smoke           GW-SMOKE-ALL-PASS
sign_selftest      SIGN-SELFTEST-ALL-PASS
integration_test   INTEGRATION-PASS
```

Run from `src/`: `python mint_vector.py` first (refreshes time-window vectors), then `node <t>.mjs`.

### Reviewer A's 22:46 round — all 4 findings CONFIRMED FIXED ON DISK

`review/verdict_bunnyA_one.json` (22:46) returned ISSUES with 4 findings. All four are
present in `src/index.js` right now (grep-verified at the cited lines):

| # | Finding | Fix on disk | Line |
|---|---|---|---|
| 1 | facilitator throw leaves `v.payer` null → stranded funds | publish `info.payer` **before** the facilitator call | 453 |
| 2 | relayed `parsed.status` unbounded → secret leak | `safeStatus` bound ≤60 chars + credential regex | 700–701 |
| 3 | responses label a non-durable refund `queued` | all `queued` → `required` | 512, 605, 634, 659, 703 |
| 4 | same, plus 2xx-with-failure-status delivered as success | `engine_reported_failure` + refund | 698–704 |

Reviewer B PASSed at **15:44** — that is a **stale PASS**: it graded a tree ~7 hours older
than the current one, before any of the above fixes. **Do not count it.**

### Uncommitted work

```
 M src/index.js        (R88–R91 fixes)
 M src/e2e_vector.json (re-minted vectors)
```
Last commit: `9b46560` "R85-R87: single pre-settle claim, timeout no-auto-refund, syntax repair" (22:42).

### No concurrent writer

Repo quiescent since 22:46. The only live harness process on this box belongs to a
different project (`AppData/Local/Temp/or-mon-review`) and a `run_seat.py` under
`PCBGenius_Local` — neither touches this repo. **This session may take ownership.**

## 4. GAPS FOUND DURING THIS HANDOFF (do not trust these files)

1. **`REVIEW_LEDGER.md` is badly stale.** It stops at R23 and still lists
   *"Settlement not wired … uncollectible-by-design"* in BACKLOG. **That is FALSE now** —
   settlement is wired via `cdpVerifyAndSettle` + `src/cdp.js` (commits `1d646a9` … `9b46560`).
   The ledger also describes a `gpt-5.6-sol` + `fable5` judge pair; the harness now pins
   **both seats to `stealth/space-bunny-alpha`**. Update or archive it before go-live.
2. **Both reviewers ran the SAME prompt.** `review_harness.py bunnyA one src/index.js` and
   `… bunnyB one src/index.js` both resolve to config `one` ⇒ identical `FOCUS_ONE`, identical
   model. Two identical runs agreeing is weak evidence, not dual review. For the next round
   give the legs **different framings** (e.g. `bunnyA one src/index.js` and `bunnyB security`)
   so agreement is meaningful.
3. **The `code` config is missing a file** — `_CONFIG_CODE_FILES` lists `src/x402.js`,
   `src/_secp256k1.js`, `src/spendguard.js`, `src/budget.js`, `src/replay-store.js`,
   `src/cdp.js`, `public/*`, `worker/*`. Confirm all exist before running a full-config round.

## 5. NOT DEPLOYED — deployment blockers

`wrangler.jsonc` still has `"SECURITY_KV", "id": "REPLACE_WITH_KV_NAMESPACE_ID"`.
Nothing is live. Before first deploy: create the KV namespace + paste the id, apply the
`ConsumedTxStore` DO migration, `wrangler secret put` the `RUNPOD_*`, `R2_*`, `CDP_*`
secrets, then make **one real self-paid conversion** — per `MARKETS.md` that single settled
payment *is* the registration event for auto-indexing (directory forms do not index you).

## 6. NEXT ACTION, in value order

1. **Get user authorization first.** The last genuine instruction was `confirm only`.
   Nothing may be changed until they say otherwise.
2. On approval: fresh **round 18** — commit the R88–R91 work, then run two reviewers
   **serially on the same frozen tree**, with **different** configs (§4.2), `source_drift`-style
   snapshot discipline. Loop until BOTH PASS. Never ship past the gate.
3. Update/replace `REVIEW_LEDGER.md` (§4.1).
4. Deployment work (§5).

## 7. Watch-outs

- Model: `stealth/space-bunny-alpha` for **every** seat and subagent. Never substitute a judge.
- Reviewer legs are **serial, never parallel**, and must grade the **same tree**.
  Any file edit mid-round voids that round (`source_drift`).
- `complete:false` + `error` in a verdict = **transport drop**, not a finding. Re-run the round.
- `NO_VERDICT` ≠ PASS. OpenRouter reserves prompt+max_tokens against the key limit — a
  reasoning model can return empty; force `finish_reason:"stop"` and raise `max_tokens`.
- Windows: `review_harness.py` takes a **relative** file arg and must be run with `cd` into
  the repo root. Windows-native tools do not understand MSYS `/c/...` paths.
- `python`, not `python3`, for the suites (3.11).
- Assert on **AST/structure**, never on raw substrings — the code's own docstrings document
  the absence of things and will make a naive `"x" not in src` assertion fire on correct code.

## 8. Credentials

Never inline. Live secrets live in `wrangler` bindings and `~/.openrouter_key`
(acct1) / `~/.openrouter_key_acct2` (acct2) — the user assigns ONE key per task; never swap.
The public merchant wallet `0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83` is a public var, safe
in `wrangler.jsonc`. No private key belongs in this repo.
