# ROTATE BEFORE GO-LIVE — credentials disclosed in chat

**These values were pasted into the Hermes chat on 2026-10-04. Chat logs are
permanent and local archives are not access-controlled. Treat both as COMPROMISED
and rotate before the service takes real money.**

| Item | Value (excerpt) | Exposure | Action required |
|---|---|---|---|
| CDP API key ID | `bba7582b-…` | full chat log + any export | rotate in portal.cdp.coinbase.com |
| CDP API secret | `TlTA4DqKulygxcL…` | full chat log + any export | **rotate** — this signs settlement requests |
| RunPod API key | `rpa_3Z969LQH…` | full chat log + any export | rotate in runpod.io console |
| Docker Hub PAT | `dckr_pat__jeK22zX…` | full chat log; also used to push the engine image | rotate in Docker Hub → Access Tokens |
| GitHub PAT | `ghp_FnLJBh8h…` | full chat log **and embedded in the git remote URL** | rotate on GitHub, then update the remote URL |

## The GitHub PAT is inside the git remote URL

`git remote -v` shows
`https://louiehub16:ghp_…@github.com/louiehub16/csv-parquet-x402.git`, so the token
is stored in plaintext in `.git/config` on this machine. Rotating the PAT will
break `git push` until the remote is updated:

```bash
git remote set-url origin https://<new-token>@github.com/louiehub16/csv-parquet-x402.git
```

## Rules applied while working with them

- NEVER write any of these values into a tracked repo file, a `.env` that gets
  committed, a handoff document, a review round directory, or memory.
- Never echo a secret value into a tool result that gets pasted back into chat.
  Reference them by NAME and say "present" / "absent".
- They go into the Worker as `wrangler secret put` values (stored by Cloudflare,
  never in `wrangler.jsonc`), and into RunPod as endpoint env vars.

## Rotation procedure (do this BEFORE the first real payment)

1. **Coinbase CDP** — portal.cdp.coinbase.com → API keys → create a NEW key pair →
   update the Worker's `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` secrets →
   delete the disclosed pair.
2. **RunPod** — console → Settings → API keys → generate a new key → update the
   RunPod endpoint's env AND the Worker's `RUNPOD_API_KEY` secret → revoke
   `rpa_3Z969LQH…`.
3. Re-verify after rotation: the facilitator still verifies and settles, and the
   engine still authenticates.

## Pre-deploy secret sweep (already run, result recorded)

- No `.env` / `.dev.vars` / secrets file exists in the project.
- `x402_wallet_project.json` holds the merchant **wallet** key; it is gitignored
  (`.gitignore:20`) and was confirmed absent from the commit.
- The 9 `CDP_API_KEY_SECRET = '4c0883a6…'` occurrences are all in test files and
  are the Coinbase **documentation example** value against a stubbed facilitator —
  public and harmless, not a live credential.
- Commit `674a562` passed a pre-commit gate that hard-fails if the merchant
  private key or any ≥40-char secret value is staged.