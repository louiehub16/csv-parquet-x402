// csv-parquet-x402 gateway — Cloudflare Worker (money router).
// Gate order is FAIL-CLOSED end-to-end; each gate numbered with WHY it sits
// where it sits. SPENDGUARD DROP-IN POINTS are marked inline (blocks 2, 7, 10)
// so the SpendGuard module can replace them without reordering anything.
import {
  tierForBytes, buildChallenge, verifyPayment, markNonceUsed, estimateCostUsd, consumeNonce,
} from './x402.js';
// SpendGuard (R12.5) — financial guard rails + atomic budget ledger (reviewer-hardened
// through 12 rounds on the docker-on-tap project; see REVIEW_LEDGER.md).
import * as spendguard from './spendguard.js';
import { reserveDailyBudget, getDailyBudget, reconcileDailyBudget } from './budget.js';
import { ConsumedTxStore } from './replay-store.js';

// Durable Object class must be exported from the worker entry point so the
// CONSUMED_TX_STORE binding resolves to this script at deploy time.
export { ConsumedTxStore };

const GB = 1073741824;
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, PAYMENT-SIGNATURE, X-PAYMENT, X-Expected-Amount',
  'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED',
};
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...CORS, ...extra } });

// Safe numeric env read: invalid config falls back to safe defaults so ceilings
// can NEVER be silently disabled by NaN (parseFloat('abc') === NaN and every
// `cost > NaN` comparison is false — i.e. a typo'd env var would remove the cap).
function numEnv(v, d){const n=parseFloat(v);return Number.isFinite(n)&&n>=0?n:d;}

const LANDING = `<!doctype html><html><head><meta charset="utf-8"><title>CSV-to-Parquet Stream Compressor — x402</title>
<style>body{background:#0d1117;color:#e6edf3;font-family:ui-monospace,monospace;max-width:820px;margin:40px auto;padding:0 20px}
table{border-collapse:collapse;width:100%;margin:16px 0}td,th{border:1px solid #30363d;padding:6px 10px;text-align:left}
th{background:#161b22}code{color:#79c0ff}h1{font-size:1.4em}</style></head><body>
<h1>CSV-to-Parquet Stream Compressor</h1>
<p>Converts .csv / .tsv / .txt uploads into ZSTD-compressed Apache Parquet.
Today's public endpoint accepts uploads up to roughly 100 MB per request while direct streaming ingestion is being rolled out; multi-GB tiers are on the roadmap (presigned direct-to-storage upload); see /llms.txt for current status.</p>
<table><tr><th>Size</th><th>Price (USDC on Base)</th><th>Storage</th></tr>
<tr><td>&lt; 100 MB</td><td>$0.01 flat</td><td>internal (24 h)</td></tr>
<tr><td>100 MB – 10 GB</td><td>$0.10 / GB</td><td>internal (24 h)</td></tr>
<tr><td>10 – 100 GB</td><td>$0.05 / GB</td><td>your bucket (BYO)</td></tr>
<tr><td>100 GB – 1 TB</td><td>$0.015 / GB</td><td>your bucket (BYO)</td></tr>
<tr><td>&gt; 1 TB</td><td>$0.008 / GB</td><td>your bucket (BYO)</td></tr></table>
<p>Your first unauthenticated call returns <b>HTTP 402</b> with an x402 v2 <code>PAYMENT-REQUIRED</code>
manifest carrying the exact micro-USDC price computed from your file's byte size. Pay via x402
(USDC on Base) and retry with the <code>PAYMENT-SIGNATURE</code> header.</p>
<pre>curl -i -X POST https://HOST/v1/compress -F file=@data.csv</pre>
<p>Discovery: <a style="color:#79c0ff" href="/llms.txt">/llms.txt</a> ·
<a style="color:#79c0ff" href="/.well-known/x402.json">/.well-known/x402.json</a> ·
<a style="color:#79c0ff" href="/openapi.json">/openapi.json</a> ·
<a style="color:#79c0ff" href="/mcp/config">/mcp/config</a></p></body></html>`;

function sanitizeKey(name) {
  // Output-key sanitization (the destination-key layer). SQL strings in CSV
  // DATA are deliberately NOT rejected at input — legit datasets contain them;
  // injection risk lives in storage keys, which we reduce to [A-Za-z0-9._-].
  const stem = String(name || 'upload')
    .replace(/[\x00-\x1f\x7f\\/]+/g, '')   // control chars + path separators
    .replace(/\.{2,}/g, '.')               // collapse traversal dots
    .replace(/[^A-Za-z0-9._-]/g, '')
    .slice(0, 128);
  return (stem || 'upload') + '.parquet';
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---- CORS preflight: never touches KV/compute -------------------------
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // ---- Free routes ------------------------------------------------------
    if (request.method === 'GET' && path === '/health')
      return json({ status: 'ok', service: 'csv-to-parquet-stream-compressor' });

    if (request.method === 'GET' && path === '/')
      return new Response(LANDING, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } });

    const DISCOVERY = ['/llms.txt', '/.well-known/x402.json', '/openapi.json', '/mcp/config'];
    if (request.method === 'GET' && DISCOVERY.includes(path)) {
      // Discovery stays up even when the money route is misconfigured.
      try {
        const res = await env.ASSETS.fetch(new Request(url.toString()));
        return res.status === 200 ? res : json({ error: 'not_found' }, 404);
      } catch (e) {
        return json({ error: 'not_found' }, 404);
      }
    }

    if (request.method !== 'POST' || path !== '/v1/compress') return json({ error: 'not_found' }, 404);

    // ================= MONEY ROUTE — gates in strict order ==================
    try {
      // (0) config guard: discovery above still works if these are missing
      if (!env.MERCHANT_WALLET_ADDRESS || !env.RUNPOD_ENDPOINT_URL || !env.RUNPOD_API_KEY)
        return json({ error: 'config_error', message: 'Service wallet/upstream not configured.' }, 500);
      if (!/^https:\/\//i.test(env.RUNPOD_ENDPOINT_URL))
        return json({ error: 'config_error', message: 'RUNPOD_ENDPOINT_URL must be https.' }, 500);

      // (1) HEADER SANITY — cheap rejection before any state is touched:
      //     oversized header floods die here, never reaching KV or RunPod.
      //     EXCEPTION: x402 payment headers ('payment-signature' / 'x-payment')
      //     get a BOUNDED 2KB limit rather than full exemption — real signed
      //     payments run ~500-900 bytes, so anything beyond 2KB is abuse, and
      //     letting it through would spend KV/multipart/decode work on garbage.
      //     Well-formed-but-oversized payment attempts still reach verifyPayment
      //     under the cap and receive the priced 402 challenge there.
      let count = 0;
      let oversizedPaymentHeader = false;
      for (const [k, v] of request.headers.entries()) {
        count++;
        // >25 headers is an abuse pattern, not a payment attempt: a bare 400
        // is correct here per our documented contract (only well-shaped
        // payment requests earn the priced 402 challenge path).
        if (count > 25) return json({ error: 'too_many_headers' }, 400);
        const kLower = k.toLowerCase();
        const valueCap = (kLower === 'payment-signature' || kLower === 'x-payment') ? 2048 : 512;
        const isPaymentHeader = kLower === 'payment-signature' || kLower === 'x-payment';
        if (isPaymentHeader && new TextEncoder().encode(v).length > valueCap) {
          // Oversized payment header (review R12/R13): inbound CF headers are
          // IMMUTABLE so we cannot rewrite them here — and must not throw into
          // the generic 500. Instead remember the fact; verifyPayment will see
          // no valid signature and answer with the freshly priced 402
          // challenge, which is exactly what x402 clients react to.
          oversizedPaymentHeader = true;
          continue;
        }
        if (new TextEncoder().encode(k).length > 64 || new TextEncoder().encode(v).length > valueCap)
          return json({ error: 'header_oversized' }, 400);
      }

      // (2) RATE LIMIT + HEADER SANITY — SpendGuard (R12.5) now owns these.
      //     sanitizeHeaders: >25 headers / name>64B / value>512B => 400 (fail closed).
      //     rateLimit: per-IP sliding window via SECURITY_KV, fail-closed 503.
      // >>> SPENDGUARD DROP-IN POINT (block 2 of 3) — INSTALLED <<<
      {
        // Payment headers are size-bounded at gate 1 (2KB) and content-checked
        // by verifyPayment; SpendGuard's 512B generic cap would false-reject
        // real ~700-byte signed payments, so hide them from this pass.
        const sh = await spendguard.sanitizeHeaders(new Request(request.url, {
          method: 'POST', headers: [...request.headers].filter(
            ([k]) => k.toLowerCase() !== 'payment-signature' && k.toLowerCase() !== 'x-payment'),
          body: null,
        }));
        if (!sh.ok) return json({ error: 'header_sanity_failed' }, sh.status);
        const ip = request.headers.get('cf-connecting-ip') || 'unknown';
        const rl = await spendguard.rateLimit(env, ip);
        if (!rl.ok) return json(rl.note ? { error: 'rate_limited', note: rl.note } : { error: 'rate_limited' }, rl.status);
      }

      // (3) SHAPE — multipart parse + extension whitelist before any pricing.
      //     HONEST CAP: request.formData() buffers the whole upload in isolate
      //     memory (~128 MB practical ceiling); the multi-GB tiers assume
      //     presigned-direct ingestion (roadmap). Comment only — no rejection.
      let form;
      try { form = await request.formData(); } catch (e) { return json({ error: 'bad_multipart' }, 400); }
      const file = form.get('file');
      if (!file || typeof file === 'string') return json({ error: 'file_field_required' }, 400);
      const fname = (file.name || '').toLowerCase();
      if (!/\.(csv|tsv|txt)$/.test(fname)) return json({ error: 'unsupported_extension' }, 400);

      // (4) BYO-STORAGE RULE — >=10 GB must bring its own destination; we will
      //     not host big outputs (liability cap).
      const size = file.size;
      const targetDestination = form.get('target_destination');
      if (size >= 10 * GB && !targetDestination)
        return json({ error: 'byo_storage_required', message: 'Files 10 GB or larger require a target_destination (JSON: endpoint_url, bucket_name, aws_access_key_id, aws_secret_access_key, file_path).' }, 400);

      // (5) CONTENT SNIFF — first 1 MB only (streaming-friendly): encoding,
      //     NUL bytes, delimiter presence, archive magic. SQL keywords are NOT
      //     scanned (legit CSV data; see sanitizeKey instead).
      {
        const head = await file.slice(0, 1048576).arrayBuffer();
        const bytes = new Uint8Array(head);
        if ((bytes[0] === 0x50 && bytes[1] === 0x4b) || (bytes[0] === 0x1f && bytes[1] === 0x8b) ||
            (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46))
          return json({ error: 'archive_or_binary_detected' }, 400);
        let text;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
        catch (e) { return json({ error: 'invalid_utf8' }, 400); }
        if (text.includes('\u0000')) return json({ error: 'null_byte_detected' }, 400);
        if (![/[,]/, /[;]/, /\t/, /\n/].some((re) => re.test(text)))
          return json({ error: 'no_delimiters_detected' }, 400);
      }

      // (5.5) OUTPUT SANITIZATION — sanitize BOTH the stored filename and any
      //       BYO target_destination BEFORE anything downstream sees them.
      const safeName = sanitizeKey(file.name);
      let dest = null;
      if (targetDestination) {
        try { dest = JSON.parse(targetDestination); } catch { return json({ error: 'bad_target_destination' }, 400); }
        // Must be a plain object (not null, not an array) and carry every
        // required BYO-storage credential as a non-empty string.
        if (typeof dest !== 'object' || dest === null || Array.isArray(dest))
          return json({ error: 'bad_target_destination' }, 400);
        const missing = ['endpoint_url', 'bucket_name', 'aws_access_key_id', 'aws_secret_access_key']
          .filter((f) => typeof dest[f] !== 'string' || dest[f].length === 0);
        if (missing.length > 0)
          return json({ error: 'bad_target_destination', missing }, 400);
        // R18/R26: TLS-only AND SSRF guard — block cloud-metadata and private
        // network targets; only public https S3-compatible endpoints allowed.
        if (!/^https:\/\//i.test(dest.endpoint_url))
          return json({ error: 'insecure_destination_endpoint' }, 400);
        try {
          const epHost = new URL(dest.endpoint_url).hostname;
          const blocked = /^(169\.254\.|10\.|127\.|0\.0\.0\.0$|100\.(6[4-9]|[7-9]\d|1[01]\d)\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|198\.(1[89])\.|\[::1\]|\[f[eE]80:)/;
          // OX-ALPHA SSRF extension: URL parsers normalize alternative IP
          // encodings before dialing, so dotted-quad checks alone are not
          // enough to keep BYO targets off private infrastructure:
          //   - all-numeric host    -> decimal integer IP ('2130706433' == 127.0.0.1)
          //   - 0x-prefixed hex     -> hex-encoded IP ('0x7f000001')
          //   - [fc..: / [fd..:    -> IPv6 unique-local (fc00::/7)
          const numericIpHost = /^\d+$/.test(epHost);
          const hexIpHost = /^0[xX][0-9a-fA-F]+$/.test(epHost);
          const ipv6UlaHost = /^\[[fF][cCdD]/.test(epHost);
          if (blocked.test(epHost) || numericIpHost || hexIpHost || ipv6UlaHost ||
              epHost === 'localhost' ||
              epHost === 'metadata.google.internal' || epHost.endsWith('.internal') ||
              epHost.endsWith('.local'))
            return json({ error: 'forbidden_destination_host' }, 400);
        } catch (_) {
          return json({ error: 'bad_target_destination' }, 400);
        }
        // Keep only the basename, then run it through the same key sanitizer.
        if (dest.file_path) dest.file_path = sanitizeKey(dest.file_path.replace(/\\/g, '/').split('/').pop());
      }

      // (6) TIER + COST CEILING — internal jobs carry R2 hosting liability, so
      //     they get the tighter cap; BYO jobs may be long but costless to host.
      const tier = tierForBytes(size);
      const est = estimateCostUsd(size, env);
      // numEnv: a NaN/garbage ceiling env var must fail SAFE (default cap),
      // never disable the cap.
      const cap = numEnv(tier.requiresUserDest ? env.SG_MAX_USERDEST_JOB_COST : env.SG_MAX_JOB_COST, tier.requiresUserDest ? 25 : 0.50);
      if (est > cap)
        return json({ error: 'ceiling_exceeded', estimated_cost_usd: Number(est.toFixed(4)), cap_usd: cap }, 400);

      // (7) DAILY BUDGET BREAKER (SpendGuard DO) — NON-MUTATING pre-check here:
      //     reserveDailyBudget MUTATES the ledger, so calling it pre-payment
      //     would let unauthenticated requests drain the day's budget
      //     (review R10-2). Here we only early-exit if today's spend is
      //     already at/over cap; the atomic RESERVATION itself happens after
      //     payment verification (gate 8.6).
      // >>> SPENDGUARD DROP-IN POINT (block 1 of 3) — INSTALLED <<<
      {
        const res = await getDailyBudget(env); // READ-ONLY (R16): no ledger mutation pre-payment
        if (!res.ok) return json({ error: 'budget_state_unavailable', note: res.note }, 503);
        if (res.spentUsd >= res.capUsd) return json({ error: 'daily_budget_exhausted' }, 503);
      }

      // (8) PAYMENT VERIFY — challenge carries the EXACT tier price; the
      //     signed authorization must commit to exactly that amount.
      if (oversizedPaymentHeader) {
        // Priced 402 (not a bare 400): x402 clients only act on 402 challenges.
        return buildChallenge({
          url: request.url,
          description: 'CSV/TSV/TXT to Parquet conversion',
          microUsdc: tier.microUsdc,
          maxTimeoutSeconds: 600,
          payTo: env.MERCHANT_WALLET_ADDRESS,
          statusNote: 'payment header exceeds 2048-byte limit',
        });
      }
      const v = await verifyPayment(env, request, { expectedAmount: tier.microUsdc });
      if (!v.ok) return v.failResponse;

      // (9) UPSTREAM DISPATCH — client disconnect aborts the upstream job too
      //     (we stop paying for abandoned work).
      // Upstream gets the SANITIZED filename and the SANITIZED destination
      // object (stringified) — raw client-supplied strings never leave here.
      // The upload name must keep a whitelisted INPUT extension (.csv/.tsv/.txt)
      // because the engine's sanitize_key whitelists input exts; '.parquet' is
      // an OUTPUT extension and would 500 every paid internal-tier job.
      const uploadName = safeName.endsWith('.parquet')
        ? safeName.slice(0, -'.parquet'.length).replace(/\.(csv|tsv|txt)$/i, '') +
          (fname.match(/\.(csv|tsv|txt)$/) || ['.csv'])[0]
        : safeName;
      const outForm = new FormData();
      outForm.append('file', new File([file], uploadName), uploadName);
      if (targetDestination) outForm.append('target_destination', JSON.stringify(dest));
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), tier.requiresUserDest ? 45 * 60 * 1000 : 10 * 60 * 1000);
      const onAbort = () => controller.abort();
      if (request.signal) {
        if (request.signal.aborted) controller.abort();
        else request.signal.addEventListener('abort', onAbort, { once: true });
      }
      //       // (8.4) RUNPOD BALANCE PREFLIGHT (SpendGuard) — after payment verify,
      //     BEFORE budget reservation: an unverifiable upstream balance must
      //     not strand a reservation (review R12).
      {
        const pb = await spendguard.preflightRunpodBalance(env);
        if (!pb.ok) {
          // OX-ALPHA (FIX-1): no reservation was made and no job will run, so
          // release the nonce claim taken in verifyPayment exactly like every
          // other post-payment failure path — the client keeps its payment
          // retryable with the SAME signature once upstream balance recovers.
          if (env.CONSUMED_TX_STORE && v && v.nonce) {
            ctx.waitUntil((async () => {
              try {
                const id = env.CONSUMED_TX_STORE.idFromName('singleton');
                const stub = env.CONSUMED_TX_STORE.get(id);
                await stub.fetch('https://internal/release-nonce', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ nonce: v.nonce }) });
              } catch (_) {}
            })());
          }
          return json({ error: 'upstream_balance_unavailable', note: pb.note }, pb.status);
        }
      }

      // (8.5) ATOMIC BUDGET RESERVATION (SpendGuard DO) — payment already
      //     verified; from here every exit path spends money, so the
      //     reservation intentionally stands (no leak possible downstream).
      const budgetTxId = 'conv-' + crypto.randomUUID();
      {
        const res = await reserveDailyBudget(env, est, budgetTxId);
        if (!res.ok) {
          // OX-ALPHA: payment was ALREADY verified & accepted above (gate 8,
          // v.ok === true) and no job will run. The nonce is deliberately
          // UNBURNED / retry-eligible (consumption only happens after success,
          // gate 10), so the client may safely retry with the SAME
          // payment-signature once budget frees up. Never consume -> never
          // burn on this path.
          // R26b: release the DO nonce claim so retry with SAME signature works.
          if (env.CONSUMED_TX_STORE && v && v.nonce) {
            ctx.waitUntil((async () => {
              try {
                const id2 = env.CONSUMED_TX_STORE.idFromName('singleton');
                const stub2 = env.CONSUMED_TX_STORE.get(id2);
                await stub2.fetch('https://internal/release-nonce', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ nonce: v.nonce }) });
              } catch (_) {}
            })());
          }
          return json({ error: 'daily_budget_exhausted', retry_nonce_unburned: true,
            note: (res.note || '') + '; payment nonce UNBURNED and retry-eligible (same signature usable on retry).' }, res.status);
        }
      }

      let upstream;
      try {
        upstream = await fetch(env.RUNPOD_ENDPOINT_URL.replace(/\/$/, '') + '/v1/compress', {
          method: 'POST',
          body: outForm,
          signal: controller.signal,
          headers: { Authorization: 'Bearer ' + env.RUNPOD_API_KEY },
        });
      } catch (e) {
              clearTimeout(timeoutId);
              if (request.signal) request.signal.removeEventListener('abort', onAbort);
              // Distinguish our timeout abort (504 Gateway Timeout, as documented)
              // from genuine upstream unreachability (502).
              if (e && e.name === 'AbortError') {
                // OX-ALPHA: an abort/timeout does NOT guarantee RunPod stopped the
                // job — compute may still be billing. Leave the reservation STANDING
                // (conservative) and release it via a subsequent reconciliation if
                // the eventual result shows a lower actual cost. Do NOT reconcile to
                // $0 here.
                // R26: release the nonce claim on timeout — client got no output.
                if (env.CONSUMED_TX_STORE && v && v.nonce) {
                  ctx.waitUntil((async () => {
                    try {
                      const id3 = env.CONSUMED_TX_STORE.idFromName('singleton');
                      const stub3 = env.CONSUMED_TX_STORE.get(id3);
                      await stub3.fetch('https://internal/release-nonce', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ nonce: v.nonce }) });
                    } catch (_) {}
                  })());
                }
                return json({ error: 'gateway_timeout' }, 504);
              }
              // R24 + OX-ALPHA: only a genuine network drop that occurs before
              // RunPod accepted (upstream_unreachable) guarantees no compute was
              // bought — RELEASE the reservation by reconciling actual cost as $0.
              // (reconcile stays on THIS path ONLY.)
              // OX-ALPHA (FIX-3): unified ':reconcile' key on ALL reconciles.
              ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', 0).catch(() => {}));
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        if (env.CONSUMED_TX_STORE && v && v.nonce) {
          ctx.waitUntil((async () => {
            try {
              const id = env.CONSUMED_TX_STORE.idFromName('singleton');
              const stub = env.CONSUMED_TX_STORE.get(id);
              await stub.fetch('https://internal/release-nonce', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nonce: v.nonce }) });
            } catch (_) {}
          })());
        }
              return json({ error: 'upstream_unreachable' }, 502);
            }
      clearTimeout(timeoutId);
      if (request.signal) request.signal.removeEventListener('abort', onAbort);

      if (!upstream.ok) {
        // R24 + OX-ALPHA (FIX-2): a non-2xx from RunPod means no conversion
        // output was delivered — reconcile the reservation to $0 (the previous
        // code passed `est`, leaving the full estimate standing against the
        // daily ledger). OX-ALPHA (FIX-3): unified ':reconcile' key.
        ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', 0).catch(() => {}));
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        if (env.CONSUMED_TX_STORE && v && v.nonce) {
          ctx.waitUntil((async () => {
            try {
              const id = env.CONSUMED_TX_STORE.idFromName('singleton');
              const stub = env.CONSUMED_TX_STORE.get(id);
              await stub.fetch('https://internal/release-nonce', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nonce: v.nonce }) });
            } catch (_) {}
          })());
        }
        // Never relay upstream error bodies: platform messages can embed
        // request ids, storage endpoints or signed URLs. Generic error only;
        // details stay in worker logs (observability streams the raw tail).
        return json({ error: 'upstream_error', upstream_status: upstream.status }, 502);
      }
      const text = await upstream.text();
      let parsed;
      try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
      if (!parsed || typeof parsed !== 'object') {
        // OX-ALPHA (completes R24 coverage): a non-JSON body means no
        // conversion output was delivered, so treat it like the other
        // pre-output failures (upstream_unreachable / upstream_error):
        // reconcile the reservation to $0 — no compute was bought.
        // OX-ALPHA (FIX-3): unified ':reconcile' key on ALL reconciles.
        ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', 0).catch(() => {}));
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        if (env.CONSUMED_TX_STORE && v && v.nonce) {
          ctx.waitUntil((async () => {
            try {
              const id = env.CONSUMED_TX_STORE.idFromName('singleton');
              const stub = env.CONSUMED_TX_STORE.get(id);
              await stub.fetch('https://internal/release-nonce', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nonce: v.nonce }) });
            } catch (_) {}
          })());
        }
        return json({ error: 'upstream_error', upstream_status: upstream.status }, 502);
      }
      const ALLOWED = ['status','output_bucket','output_key','rows','skipped_columns','skipped_rows','drift_fallback','duration_s','estimated_cost_usd','download_url','warning'];
      const body = {};
      for (const k of ALLOWED) if (parsed[k] !== undefined) body[k] = parsed[k];
      // OX-ALPHA: settle the gate 8.5 estimate against the engine-reported
      // ACTUAL cost now that the allowlist body is built. The DO keys
      // reconciles by kind, so the ':reconcile' transaction id records the
      // adjustment without double-counting the original estimate reservation.
      // Fire-and-forget: reconciliation failure must never fail an already-
      // delivered response (compute is spent either way).
      const actual = typeof body.estimated_cost_usd === 'number' ? body.estimated_cost_usd : est;
      ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', actual).catch(() => {}));
      // Deficit audit: deliver anyway (compute already spent) but flag the
      // underpayment loudly. Engine reports cost as estimated_cost_usd;
      // engine_cost_usd kept as a legacy field-name fallback.
      const ec = body.estimated_cost_usd ?? body.engine_cost_usd;
      if (typeof ec === 'number' && v.amountMicro / 1e6 < ec)
        body.spend_warning = 'paid below engine cost';

      // (10) SETTLE BOOKKEEPING — allowlist body is built FIRST; then both
      //      state writes are AWAITED inline before the response leaves so
      //      failures are visible on the body instead of vanishing into
      //      background tasks:
      //        - nonce burn failure -> body.replay_risk (authorization remains
      //          replayable until validBefore),
      //        - daily-ledger failure -> body.spend_warning append.
      //      Upstream errors already returned above, so reaching this point
      //      means delivered success.
      // R20 CONSUME-AFTER-SUCCESS: atomically consume the nonce NOW via the
      // DO (strongly consistent). Fail-closed: if consumption cannot be
      // confirmed we refuse delivery — a replayable paid output is worse
      // than a retry. KV fallback burns best-effort with documented race.
      // R25: nonce was atomically CLAIMED at gate 8 via DO reserve-nonce; the
      // claim IS permanent consumption. No further burn needed on DO path.
      // KV fallback deployments still burn here (best-effort, documented race).
      if (!env.CONSUMED_TX_STORE) {
        try {
          await markNonceUsed(env, v.nonce, v.validBefore);
        } catch (e) {
          // OX-ALPHA: KV burn failed -> reconcile to est (NOT $0) since the job
          // ran and billed compute; refusing delivery would waste it.
          // OX-ALPHA (FIX-3): unified ':reconcile' key here too (amount stays
          // est — the job genuinely billed compute).
          ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', est).catch(() => {}));
          return json({ error: 'nonce_consumption_failed' }, 503);
        }
      }

      return json(body, upstream.status);
    } catch (e) {
      // FAIL-CLOSED catch-all: an internal error never becomes a free job.
      return json({ error: 'internal_error' }, 500);
    }
  },
};
