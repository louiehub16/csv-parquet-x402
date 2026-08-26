# Market Posting & Auto-Discovery Runbook — CSV-to-Parquet Stream Compressor

Live URL assumed throughout: `https://csv-parquet.YOURDOMAIN.workers.dev` (replace everywhere).
Scope: how this service gets listed/discovered across the x402 ecosystem, what actually triggers auto-indexing, and which manual submissions are worth doing.

---

## Core facts (proven on sibling project, 2026-08)

1. **Directories are listings only.** None of the aggregator sites process payments. All money moves through the x402 payment rail between our gateway and the caller's wallet, settled by the facilitator.
2. **ONE facilitator-settled route serves all traffic.** There is no per-directory integration. Coinbase's CDP facilitator settles every real payment regardless of which directory the client discovered us through.
3. **Auto-indexing is triggered by settlement, not submission.** Auto-indexing into the Coinbase CDP Bazaar + x402scan happens when a settled payment is observed flowing through the CDP facilitator. Filling out directory submission forms does **NOT** cause auto-indexing.
4. **One real test payment post-deploy IS the registration event.** A single genuine, self-paid conversion after deploy is what flips you from "not indexed" to "indexed" on both auto surfaces.
5. **Verify indexing via discovery API:**
   `GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?query=<name>`
6. **CDP keys:** create at `portal.cdp.coinbase.com` → API Keys. The API secret is shown **ONCE** — copy it immediately. No business KYC required for facilitator use.
7. **Dynamic per-byte pricing lives inside our 402 manifests.** Directories display static price *ranges* scraped/cached at index time. The live manifest returned in each HTTP 402 response is authoritative.

---

## Pricing Matrix

| Tier | Bytes [min, max) | Rate | Storage |
|---|---|---|---|
| 1 | 0 – 104857600 | $0.01 flat | internal R2 (24h retention) |
| 2 | 104857600 – 10737418240 | $0.10/GB | internal R2 (24h retention) |
| 3 | 10737418240 – 107374182400 | $0.05/GB | BYO destination (required ≥10GB) |
| 4 | 107374182400 – 1099511627776 | $0.015/GB | BYO destination |
| 5 | 1099511627776 – ∞ | $0.008/GB | BYO destination |

Minimum charge $0.01. Exact micro-USDC amount computed from byte size is returned in every live 402 PAYMENT-REQUIRED manifest — authoritative over any directory's displayed range.

---

## Phase 0 — Prerequisites [FREE]

1. Create KV namespace and wire the id:
   ```bash
   npx wrangler kv namespace create SECURITY_KV
   ```
   Paste the returned namespace `id` into `wrangler.jsonc`.

2. Set every secret (run once each, paste values when prompted):
   ```bash
   npx wrangler secret put RUNPOD_ENDPOINT_URL
   npx wrangler secret put RUNPOD_API_KEY
   npx wrangler secret put R2_ENDPOINT_URL
   npx wrangler secret put R2_ACCESS_KEY_ID
   npx wrangler secret put R2_SECRET_ACCESS_KEY
   npx wrangler secret put R2_BUCKET_NAME
   npx wrangler secret put CDP_API_KEY_ID
   npx wrangler secret put CDP_API_SECRET
   ```

3. Build & push the compression engine image:
   ```bash
   docker build -t hrm3478938/x402-parquet-engine worker/
   docker push hrm3478938/x402-parquet-engine
   ```

4. Create the RunPod serverless endpoint from that image: **CPU type**, **HTTP port 8000**.

5. Create R2 bucket `x402-parquet-tmp`; add lifecycle rule: prefix `outputs/`, expire objects after **1 day**. (apply `r2-lifecycle.json` from the repo)

## Phase 1 — Deploy + smoke test [FREE]

```bash
npx wrangler deploy

curl -i https://csv-parquet.YOURDOMAIN.workers.dev/health
```
Expect `200 OK` and a healthy JSON body.

Trigger the paywall path without paying:
```bash
curl -is -X POST https://csv-parquet.YOURDOMAIN.workers.dev/v1/compress | grep -i PAYMENT-REQUIRED
```

Decode the PAYMENT-REQUIRED **header** to confirm pricing/accepts block (the manifest rides in a base64url-encoded response header, not the body):
```bash
curl -sD headers.txt -o /dev/null -X POST https://csv-parquet.YOURDOMAIN.workers.dev/v1/compress
python - <<'EOF'
import base64, re
raw = [l for l in open('headers.txt') if l.lower().startswith('payment-required:')][0]
tok = raw.split(':',1)[1].strip()
tok += '=' * (-len(tok) % 4)          # restore base64url padding
import json
manifest = json.loads(base64.urlsafe_b64decode(tok))
print(json.dumps(manifest, indent=2))
EOF
```
Confirm the decoded manifest — payTo, asset = USDC on Base, amount, and resource URL all look right.

## Phase 2 — Registration payment [~$0.01]

1. Fund the **customer-side** wallet: ~$5 USDC + ~$2 ETH (gas) **on Base**.
2. Perform **one real, self-paid conversion** through your own gateway (act as a customer, pay the 402 challenge for real).
3. The CDP facilitator settles the payment. **This settlement IS the registration event** — auto-indexing into CDP Bazaar + x402scan begins from this moment.

Do not skip this because smoke tests passed: unpaid requests never reach the facilitator and therefore never register anything.

## Phase 3 — Verify indexing [FREE]

Query the discovery API for both your product name and your domain:
```
GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?query=csv-to-parquet-stream-compressor
GET https://api.cdp.coinbase.com/platform/v2/x402/discovery/search?query=csv-parquet.YOURDOMAIN.workers.dev
```
Lag is **minutes-to-hours** after the Phase 2 settlement — don't panic if the first poll misses. Poll again before concluding failure.

## Phase 4 — Manual submissions (~20 min total)

These get you listed on non-auto directories. None of them affect payments; they're pure discovery surface.

| Directory | Method | Payload |
|---|---|---|
| **x402scan** | Submit form at `https://x402scan.com` | endpoint URL + description |
| **x402-list.com** | `POST https://x402-list.com` | JSON `{'url': '<live-url>'}` |
| **x402list.fun** | `POST https://x402list.fun` | JSON `{'url': '<live-url>'}` |
| **relai.fi** | Developer portal submit form | endpoint URL + description |
| **Agentic.Market** | Connect wallet + submit endpoint URL | gateway auto-passes its $0.01 challenge because we speak real x402 v2 |

Note on Agentic.Market: no special handling needed — its verification challenge is itself an x402 v1/v2 request our gateway answers correctly by construction.

## Phase 5 — Ongoing ops

**Secret rotation (zero downtime):**
1. Create NEW key in the vendor dashboard (CDP portal, R2, RunPod).
2. `wrangler secret put <NAME>` with the new value — Workers pick up secrets atomically.
3. Revoke the OLD key only after a successful paid round-trip.
4. Indexing status is unaffected by rotation.

**Do NOT run dual rails.** One facilitator, one route. Parallel payment paths split settlements across facilitators and can silently break auto-indexing.

**Tier-3/4 portals** (Thirdweb Nexus, Circle Arc, Nadles, Nevermined, Fetch.ai, LobeHub, etc.): optional listings with unclear automation value. Treat as last / if-ever — do not spend engineering time here before Phases 0–4 are verified green.

---

## GO-LIVE CHECKLIST

- [ ] Phase 0: KV namespace created; id pasted into `wrangler.jsonc`
- [ ] Phase 0: all 8 secrets set (`RUNPOD_*`, `R2_*`, `CDP_*`)
- [ ] Phase 0: engine image built & pushed (`hrm3478938/x402-parquet-engine`)
- [ ] Phase 0: RunPod serverless endpoint live (CPU, port 8000)
- [ ] Phase 0: R2 bucket `x402-parquet-tmp` + `outputs/` 1-day lifecycle rule
- [ ] Phase 1: `wrangler deploy` succeeded
- [ ] Phase 1: `/health` returns 200
- [ ] Phase 1: POST `/v1/compress` returns 402 with valid base64 manifest
- [ ] Phase 2: customer wallet funded (~$5 USDC + ~$2 ETH on Base)
- [ ] Phase 2: ONE real self-paid conversion completed; facilitator settled
- [ ] Phase 3: discovery/search finds us by name AND domain
- [ ] Phase 4: x402scan submitted
- [ ] Phase 4: x402-list.com POSTed
- [ ] Phase 4: x402list.fun POSTed
- [ ] Phase 4: relai.fi developer portal submitted
- [ ] Phase 4: Agentic.Market endpoint submitted ($0.01 challenge passed)

---

## Honest caveats — vendor-doc features that DO NOT exist

Proven absent on the sibling project (2026-08). Don't burn time looking for them:

- **`cdp x402 register` CLI command** — does not exist. Registration = facilitator-settled payment (Phase 2).
- **Cloudflare dashboard "Monetization Gateway" toggle** — does not exist. The gateway is our own Worker code.
- **Thirdweb / Circle / Nadles auto-registration flows** — none exist. At best these are manual listings (Tier-3/4).

Everything above is replaced by the one method that works: **deploy → one real self-paid conversion → facilitator settles → you're registered.**
