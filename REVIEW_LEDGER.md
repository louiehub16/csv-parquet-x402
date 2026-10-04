# Review Ledger — csv-parquet-x402

**Status: dual PASS at round 83** (uncommitted working tree on top of commit
`b0d8ba4`), **42/42 suites green**, `source_drift: []` on the passing round.

Evidence: `review/r83/verdict_bunnyA_security.json` and
`review/r83/verdict_bunnyB_code.json` are both `{"verdict":"PASS","reasons":[]}`,
both with `finish_reason: stop` (real verdicts, not transport drops), and
`python review/make_manifest.py review/r83 --check` reports `source_drift: []`.
Reproduce with `python _gate.py`.

**Known standing caveat, unchanged:** 6 of the earlier 59 rounds were genuine dual
passes and **five of those six were followed by further defects.** A single dual pass
is *not* evidence of convergence — the most important fact in this ledger.

This file replaces the previous ledger, which stopped at round R23 and was
materially wrong: it claimed *"Settlement not wired — delivered conversions are
UNCOLLECTIBLE"* and named a `gpt-5.6-sol` / `fable5` judge pair. Settlement has
been wired since commit `1d646a9`, and the harness pins a single model for both
seats. **Do not trust the old copy of this file.**

---

## 1. What this service is

An x402 v2 paid API selling CSV/TSV/TXT → Apache Parquet conversion, priced in
micro-USDC on Base (chainId 8453) and settled through the Coinbase CDP
facilitator.

| Component | File | Role |
|---|---|---|
| Gateway | `src/index.js` | paid request path, result delivery |
| Payment core | `src/x402.js` | EIP-3009 verify, tiers, 402 manifest, `safeDiag` |
| CDP adapter | `src/cdp.js` | facilitator verify + settle |
| SpendGuard | `src/spendguard.js`, `budget.js` | rate limit, budget breaker |
| Replay store | `src/replay-store.js` | Durable Object: nonce claims, refunds, budget ledger |
| Curve math | `src/_secp256k1.js` | EIP-712 recovery, deterministic signing |
| Engine | `worker/main.py` | streaming CSV → Parquet on RunPod |
| Engine guard | `worker/s3_guard.py` | R2 SSRF: address pinning, no redirects |

## 2. How the review gate works

Two independent seats, run **serially** on the **same frozen tree**:

| Seat | Framing | Focus |
|---|---|---|
| `bunnyA` | `security` | money loss, replay, secrets, auth |
| `bunnyB` | `code` | correctness, contract drift, integration |

Both use **`stealth/space-bunny-alpha`** only. No substitutions.

A round passes only when `verdict == "PASS"` from both seats **and**
`review/make_manifest.py <dir> --check` reports `source_drift: []`. Any source
edit mid-round voids that round.

**6 of 59 rounds on record are genuine dual passes** (r33, r49, r50, r56, r70,
r76). Five of those six were followed by further defects, so a single dual pass
is **not** evidence of convergence. This is the single most important fact in
this ledger.

## 3. The defects that mattered most

Found by reviewers **and** by running the real engine — review alone did not
surface the last four.

| Round | Defect | Impact |
|---|---|---|
| R53 | S3 SSRF: DNS rebinding + redirect following | engine could reach loopback/metadata |
| R54 | Verify-stage failure reported as `settledUnknown` | **refunded money never collected** |
| R57 | R55's 32-hex job stem rejected by the engine's 16-hex extractor | every BYO job lost its prefix |
| R61 | `s3_guard.py` not in the Dockerfile | **every conversion failed** in the image |
| R62 | R46 streamed every receipt from our bucket | **all BYO results 503'd** |
| R65 | Pre-submit exception reported as `settledUnknown` | fabricated refunds |
| R68 | `sys.exc_info()` with `sys` not module-scoped | **NameError on every conversion** |
| R70 | `.csv` hardcoded comma without reading content | semicolon CSVs silently corrupted |
| R71 | pyarrow rejects newline as a delimiter | newline-delimited files hard-failed |
| R73 | `\b`-anchored 40-char-only secret regex | 14/18/20/23-char secrets leaked 8 chars |
| R74 | Engine had **no authentication** | **anyone with the URL converted for free** |
| R75 | `R2Bucket.get()` is async and was unawaited | **every paid download returned an empty body** |

R74 and R75 are the reason the first "dual pass" was not trusted: both were
live-money defects sitting behind a green suite, because the tests mocked the
very surfaces that were wrong.

## 4. Test-suite lessons (the durable part)

Every defect above slipped past a passing suite. Four recurring causes:

1. **Mocks modelled the wrong contract.** `R2Bucket.get()` was mocked
   synchronously; it is async. The engine's bearer token was never modelled at all.
   *Rule: when a mock is the only thing exercising a boundary, check the mock
   against the real runtime shape before trusting a green.*
2. **The real engine was never run.** `pyarrow` was absent locally for most of
   the loop, so 500 lines of conversion logic ran only against stubs. Installing
   `pyarrow` (R70) immediately produced two real bugs.
   *Rule: install the actual dependency and exercise the real code path.*
3. **Text-matching assertions pass on comments.** Several "tests" asserted a
   string existed somewhere in a file — satisfiable by a comment, and in one case
   by the comment *explaining the bug*.
   *Rule: assert on behaviour, and prove the test fails when the fix is reverted.*
4. **A fix can break its own predecessor.** R46→R62, R55→R57, R73's own
   follow-on, R23→R48.
   *Rule: re-run the whole suite after every fix, and expect cross-service
   interactions to be the failure site.*

Negative controls are mandatory. Every fix in this ledger was verified by
reverting it in a sandbox copy and confirming the test fails.

## 5. Accepted, documented gaps

Open by decision, not oversight:

| Gap | Why it is still open |
|---|---|
| DNS-rebinding TOCTOU in the engine | R53 narrows it (resolve once, pin, re-check) but botocore resolves again internally. Full closure needs connection pinning, which urllib3 does not expose cleanly. Mitigations: caller-supplied credentials, SigV4 signing. |
| S3 redirect following | Same root cause. A `before-send` guard fires on **every** request and would fail all S3 operations — a worse defect. Mitigated by SigV4 (a cross-host redirect invalidates the signature). |
| Internal-result retrieval | Closed in R46/R62/R75: results stream through the Worker after receipt + EIP-712 payer verification. Requires the `RESULTS` binding and `RESULTS_BUCKET_NAME`. |

## 6. Pre-launch checklist

- [ ] Create KV namespace → set `SECURITY_KV.id` (currently `REPLACE_WITH_KV_NAMESPACE_ID`)
- [ ] Create R2 bucket → set `r2_buckets[].bucket_name` **and** `RESULTS_BUCKET_NAME`
- [ ] Set the 9 Worker secrets: `RUNPOD_API_KEY`, `RUNPOD_ENDPOINT_URL`,
      `ENGINE_API_KEY`, `R2_ENDPOINT_URL`, `R2_ACCESS_KEY_ID`,
      `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`, `CDP_API_KEY_ID`,
      `CDP_API_KEY_SECRET`
- [ ] Apply the `ConsumedTxStore` Durable Object migration
- [ ] Build the engine image **in CI** and pin the digest. Local `docker build`
      is not viable (disk at ~2.5 GB free). Verify the image's source hash
      against the reviewed tree before creating the endpoint.
- [ ] Fund `MERCHANT_WALLET_ADDRESS` with USDC on Base
- [ ] Create the RunPod CPU endpoint (`cpu5c`), set **every** env var including
      `ENGINE_API_KEY` — an endpoint with empty `env` still reports `ready:1` and
      silently dispatches jobs that cannot work
- [ ] Confirm the endpoint record shows `cpu` and **no** `gpuTypeIds`
- [ ] Run one real self-paid conversion end-to-end. Per `MARKETS.md` that single
      settled payment is the indexing event — directory forms do not index.

## 7. Environment notes

- `core.autocrlf=true` and no `.gitattributes`: the repo stores **LF**. A
  `git checkout` can write CRLF, which the byte-hash manifest correctly reports
  as `source_drift` even with zero textual diff. If drift appears with no
  `git status` change, normalise to LF.
- Windows: `python`, not `python3`. `node --check` invoked through some wrappers
  mis-resolves MSYS `/c/...` paths; `cd` and use a relative filename.
- Editing `worker/main.py` and `src/*.js` by hand is error-prone — a `patch` pass
  re-indents blocks and can silently corrupt a multi-line statement. Prefer
  `patch` with an exact block, and always re-run `node --check` / `ast.parse`
  plus the full gate afterwards.
