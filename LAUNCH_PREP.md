# Launch Prep — csv-parquet-x402 (no credentials written to any file)

**Status: dual PASS at R83, committed as `674a562`, 42/42 suites green.**
Nothing is deployed. Three placeholders still block a deploy (see §3).

---

## 1. Credential validation — MEASURED, with controls

| Credential | Result | Evidence |
|---|---|---|
| **RunPod API key** | **VALIDATED — works** | `POST api.runpod.io/graphql {myself{id}}` → HTTP 200, id `user_3H66M95f2l0RM0FoobBYVcZ89ZE`. A garbage key returns **401 "token is invalid or expired"** on the same call, so this probe genuinely discriminates. |
| **CDP API key pair** | **INCONCLUSIVE — not rejected** | `POST api.cdp.coinbase.com/platform/v2/x402/verify` → HTTP 401 for the real key, a wrong secret, **and with no Authorization header at all**. Identical responses mean the probe cannot distinguish a good key from a bad one. |

### Two probe errors I made, and their lesson

1. **I first reported "CDP KEY REJECTED — stop."** That was **wrong.** The 401 is the
   endpoint's generic refusal for a malformed request; a wrong key gives the same
   401. I had asserted a conclusion from a non-discriminating probe. Always run
   the probe against a deliberately-wrong credential before believing it.
2. **RunPod returned 404/403 at first** — those were my *wrong URLs*, plus a
   Cloudflare `403 code 1010` bot block on the default urllib User-Agent. Adding a
   browser UA fixed it. A 403 `1010` is Cloudflare, not the API.

**The CDP key still needs one real validation:** a signed EIP-3009 authorization
verified through the facilitator, or simply confirm it in the CDP dashboard. Do
**not** treat the 401 as a rejection.

---

## 2. Endpoint name requested: "CSV TO PARQUET STREAM"

The RunPod serverless endpoint should be created as:

- **Name:** `CSV TO PARQUET STREAM`
- **Type:** HTTP (not HTTPS), **port 8000**
- **GPU:** none — this is a **CPU** endpoint (`cpu5c`). Per `REVIEW_LEDGER.md`
  §6, confirm the endpoint record shows `cpu` and **no** `gpuTypeIds`.
- **Idle timeout:** 5s (nothing here is interactive)
- **FlashBoot:** off

**Every env var must be set.** An endpoint with an empty `env` still reports
`ready:1` and silently dispatches jobs that cannot work — this exact trap cost the
previous launch.

### Engine env vars (set on the RunPod endpoint)

| Var | Value |
|---|---|
| `ENGINE_API_KEY` | **generate a fresh random secret** — do not reuse any key from chat |
| `R2_ENDPOINT_URL` | the R2 S3 endpoint |
| `R2_ACCESS_KEY_ID` | R2 access key id |
| `R2_SECRET_ACCESS_KEY` | R2 secret |
| `R2_BUCKET_NAME` | the temporary-results bucket |
| `SG_CPU_RATE_PER_HR` | `0.13` |

### Worker secrets (`wrangler secret put` — never written into `wrangler.jsonc`)

`RUNPOD_API_KEY`, `RUNPOD_ENDPOINT_URL`, `ENGINE_API_KEY`, `R2_ENDPOINT_URL`,
`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`, `CDP_API_KEY_ID`,
`CDP_API_KEY_SECRET`.

`wrangler.jsonc` already lists these names in a comment block (lines 38-43) and
declares NO values — that is correct and must stay that way.

---

## 3. The three placeholders that block `wrangler deploy`

| File:line | Current value | Action |
|---|---|---|
| `wrangler.jsonc:12` | `SECURITY_KV.id` = `REPLACE_WITH_KV_NAMESPACE_ID` | `npx wrangler kv namespace create SECURITY_KV` → paste the returned id |
| `wrangler.jsonc:30` | `r2_buckets[0].bucket_name` = `REPLACE_WITH_R2_BUCKET_NAME` | `npx wrangler r2 bucket create <name>` → paste the name |
| `wrangler.jsonc:48` | `RESULTS_BUCKET_NAME` = `REPLACE_WITH_R2_BUCKET_NAME` | same bucket name |

Plus: apply the **`ConsumedTxStore` Durable Object migration** before first deploy.

Also note `x402_wallet_project.json:20` in `.gitignore` — the merchant wallet
**private key** lives in that file, is gitignored, and was confirmed absent from
commit `674a562`. Merchant wallet `0x795dCA28…` currently holds **0.0 USDC** on
Base and must be funded before the first settled payment.

---

## 4. Exact launch sequence (run in this order)

```bash
cd "/c/Users/John Doe/Desktop/csv-parquet-x402"

# 1. CF resources
npx wrangler kv namespace create SECURITY_KV
npx wrangler r2 bucket create csv-parquet-tmp
#    -> paste ids into wrangler.jsonc lines 12, 30, 48

# 2. Secrets (prompted interactively; values are NEVER echoed into a file)
for s in RUNPOD_API_KEY RUNPOD_ENDPOINT_URL ENGINE_API_KEY \
         R2_ENDPOINT_URL R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY \
         R2_BUCKET_NAME CDP_API_KEY_ID CDP_API_KEY_SECRET; do
  npx wrangler secret put "$s"
done

# 3. Verify no drift and no leaked value before deploying
python review/make_manifest.py review/r83 --check    # expect source_drift: []
python _gate.py                                       # expect 42/42 GATE ALL-GREEN

# 4. Deploy
npx wrangler deploy

# 5. Apply the DO migration (confirm the exact class name from wrangler.jsonc)
npx wrangler deploy --dry-run   # inspect first
```

## 5. Engine image — BUILT AND PUSHED (gated on the engine's own tests)

Built in GitHub Actions, not locally (disk was at ~98%). The workflow runs the
engine's 8 suites in a separate job and `build-push.needs: test`, so **no image is
published unless they pass** — which is exactly what caught the first failure.

| | |
|---|---|
| Workflow run | `37216523844` — **success** |
| Tested commit | `05e17b7616cb28f1690ec87ec7a2ad92081c5d4d` |
| Image | `hrm3478938/x402-parquet-engine` |
| **Deploy tag** | `hrm3478938/x402-parquet-engine:05e17b7616cb28f1690ec87ec7a2ad92081c5d4d` |
| **Digest** | `sha256:e8b81be8912bb4dbe3c55af513c3af73e96cf38a9a5d8b14d7a0aaeff8816b61` |
| Platforms | linux/amd64 134.3 MB, linux/arm64 131.8 MB |

Create the RunPod endpoint from the **SHA tag or the digest**. Do NOT use
`:latest` — it is a moving tag and can be repointed between the digest check and
endpoint creation. `:latest` currently resolves to the same digest, which is why
the digest above is the authoritative reference.

### The first CI run failed, and that was the gate working

Run `37215843234` exited **2 with zero assertions executed**:

```
starlette.testclient requires the httpx2 package to be installed
```

A missing TEST dependency, not a code defect — but without the gate it would have
published an image whose conversion path was never executed. Fixed by installing
`httpx httpx2` (note: `httpx2` is a REAL package on PyPI, not a typo for httpx),
verified in a clean venv built from the workflow's own install line, then re-run.

## 6. Pre-launch checklist

- [ ] Rotate the CDP key pair + RunPod key (both were pasted in chat — see
      `ROTATE_BEFORE_GOLIVE.md`)
- [ ] `ENGINE_API_KEY` freshly generated, never a chat-exposed value
- [ ] KV namespace id, R2 bucket name, `RESULTS_BUCKET_NAME` filled in
- [ ] 9 Worker secrets set
- [ ] `ConsumedTxStore` DO migration applied
- [x] Engine image built in CI at `05e17b7`, digest pinned, engine suite green in CI
- [ ] RunPod endpoint `CSV TO PARQUET STREAM` created: HTTP, port 8000, cpu5c,
      no `gpuTypeIds`, **all** env vars set
- [ ] Merchant wallet funded with USDC on Base
- [ ] CDP key validated against a real signed authorization
- [ ] One real self-paid conversion end-to-end — per `MARKETS.md` that single
      settled payment is the indexing event; directory forms do not index