// csv-parquet-x402 gateway — Cloudflare Worker (money router).
// Gate order is FAIL-CLOSED end-to-end; each gate numbered with WHY it sits
// where it sits. SPENDGUARD DROP-IN POINTS are marked inline (blocks 2, 7, 10)
// so the SpendGuard module can replace them without reordering anything.
import {
  tierForBytes, buildChallenge, verifyPayment, estimateCostUsd, consumeNonce,
} from './x402.js';
// CDP facilitator adapter (settlement rail) — installed for auto-indexing + collectibility.
import { cdpConfigured, cdpVerifyAndSettle } from './cdp.js';
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
      // R28: hoisted so the outer catch block can access them for cleanup
      let v = null;
      let budgetTxId = null;
      // R51/R55: dispatched = upstream work started; settled = payment collected.
      let paymentSettled = false;
      let upstreamDispatched = false;
      // R84: set the moment we call the facilitator.
      let settleAttempted = false;
      // R57: durable refund record for settled-but-undelivered jobs.
      // R58: release the daily-budget reservation (nothing dispatched yet).
      const releaseReservation = () => {
        if (typeof budgetTxId === 'string' && budgetTxId) {
          ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', 0).catch(() => {}));
        }
      };
      // R60: REFUNDS ARE EXECUTED, NOT PROMISED. A settled-but-undelivered
      // job enqueues an idempotent refund keyed by the nonce, attempts the
      // facilitator refund immediately, and only then reports the result.
      const recordRefund = async (reason) => {
        // R66: stable key for this refund (status persistence + idempotency).
        const refKey = 'refund:' + v.nonce;
        // R63: claim the refund ATOMICALLY through the DO so two concurrent
        // retries can never both execute the same refund.
        if (!env.CONSUMED_TX_STORE) {
          // Without the DO we cannot claim atomically — refuse to refund rather
          // than risk double-spending the payer's money back.
          console.error('[gateway] no DO: cannot claim refund atomically', v.nonce);
          return false;
        }
        const dId = env.CONSUMED_TX_STORE.idFromName('singleton');
        const dStub = env.CONSUMED_TX_STORE.get(dId);
        const claim = await dStub.fetch('https://internal/claim-refund', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nonce: v.nonce, payer: v.payer,
            amountUsdc: tier.microUsdc, reason, at: Date.now() }),
        }).catch(() => null);
        if (!claim) return false;
        const cj = await claim.json().catch(() => null);
        if (!cj || cj.ok !== true) return false;      // already claimed/refunded
        if (cj.alreadyRefunded === true) return true; // another attempt completed it
        // R83: the DO claim IS the durable record (it persists the claim in
        // its own storage partition). KV is a convenience mirror only.
        const record = { nonce: v.nonce, payer: v.payer, amountUsdc: tier.microUsdc,
          reason, at: Date.now(), status: 'claimed' };
        await env.SECURITY_KV.put('refund:' + v.nonce, JSON.stringify(record),
          { expirationTtl: 604800 }).catch(() => {});
        // Attempt execution now. The operator sweep (or the next call) retries
        // any still-queued refund; the client is told the true state.
        if (typeof env.X402_REFUND_URL === 'string' && env.X402_REFUND_URL) {
          let refundUrl = null;
          try {
            const u = new URL(env.X402_REFUND_URL);
            // R83: the refund call carries a bearer secret — HTTPS only.
            if (u.protocol !== 'https:') {
              console.error('[gateway] refusing insecure refund endpoint');
            } else {
              refundUrl = u.toString();
            }
          } catch (e) { refundUrl = null; }
          if (refundUrl) {
          try {
            const resp = await fetch(refundUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json',
                Authorization: 'Bearer ' + (env.X402_REFUND_SECRET || '') },
              body: JSON.stringify({ nonce: v.nonce, payer: v.payer,
                amountUsdc: tier.microUsdc, reason }),
            });
            if (resp.ok) {
              record.status = 'refunded';
              await env.SECURITY_KV.put(refKey, JSON.stringify(record),
                { expirationTtl: 604800 }).catch(() => {});
              try {
                const mId = env.CONSUMED_TX_STORE.idFromName('singleton');
                await env.CONSUMED_TX_STORE.get(mId).fetch('https://internal/mark-refunded', {
                  method: 'POST', headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ nonce: v.nonce }) });
              } catch (_) {}
              return true;
            }
          } catch (e) { /* stays queued for the sweep */ }
          }
        }
        return false;
      };
      // R62: HARD UPLOAD CEILING. formData() buffers the entire body in
      // isolate memory, so reject oversize uploads BEFORE parsing. The public
      // cap is ~100 MB; allow a small margin for multipart framing.
      const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
      const clen = Number(request.headers.get('content-length') || 0);
      if (Number.isFinite(clen) && clen > MAX_UPLOAD_BYTES) {
        return json({ error: 'upload_too_large', max_bytes: MAX_UPLOAD_BYTES }, 413);
      }

      // R82: read the body ONCE with a hard byte ceiling. A chunked request has
      // no Content-Length, so the pre-check above cannot be trusted alone.
      let rawBody;
      try {
        const reader = request.body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > 128 * 1024 * 1024) {
            try { await reader.cancel(); } catch (_) {}
            return json({ error: 'upload_too_large', max_bytes: 128 * 1024 * 1024 }, 413);
          }
          chunks.push(value);
        }
        rawBody = new Uint8Array(total);
        let o = 0;
        for (const c of chunks) { rawBody.set(c, o); o += c.length; }
      } catch (e) {
        return json({ error: 'bad_multipart' }, 400);
      }
      let form;
      try { form = await new Response(rawBody, { headers: request.headers }).formData(); }
      catch (e) { return json({ error: 'bad_multipart' }, 400); }
      const file = form.get('file');
      if (file && typeof file.size === 'number' && file.size > 128 * 1024 * 1024) {
        return json({ error: 'upload_too_large', max_bytes: 128 * 1024 * 1024 }, 413);
      }
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
        try {
          // Strip trailing bytes that could be part of a truncated multi-byte
          // UTF-8 sequence at the 1 MB slice boundary (R26 fix: false invalid_utf8).
          let end = bytes.length;
          while (end > 0 && (bytes[end - 1] & 0xC0) === 0x80) end--;
          if (end > 0 && (bytes[end - 1] & 0x80) !== 0) end--; // strip lead byte too
          text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.slice(0, end));
        } catch (e) { return json({ error: 'invalid_utf8' }, 400); }
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

      // The nonce the settlement callback must burn (read from the header the
      // verifier authenticated).
      let v0Nonce = null;
      {
        const h = request.headers.get('PAYMENT-SIGNATURE') || request.headers.get('X-PAYMENT') || '';
        try { const dec = JSON.parse(atob(h.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice(0, (4 - h.length % 4) % 4)));
              v0Nonce = dec?.payload?.authorization?.nonce
                ? String(dec.payload.authorization.nonce).replace(/^0x/, '').toLowerCase() : null; }
        catch (e) {}
      }

      // (7.9) RUNPOD BALANCE PREFLIGHT (SpendGuard) — BEFORE any payment, so we
      //     never settle for work an unfunded upstream cannot run.
      {
        const pb = await spendguard.preflightRunpodBalance(env);
        if (!pb.ok) return json({ error: 'upstream_balance_unavailable', note: pb.note }, pb.status);
      }

      // (7.95) ATOMIC BUDGET RESERVATION (SpendGuard DO) — before settlement;
      //     a rejected job must never have charged the payer. Fully released
      //     again by the catch-all (nothing is dispatched at this point).
      budgetTxId = 'conv-' + crypto.randomUUID(); // assign the hoisted binding
      {
        const res = await reserveDailyBudget(env, est, budgetTxId);
        if (!res.ok)
          return json({ error: 'daily_budget_exhausted', note: res.note }, res.status || 503);
      }

      // (8) PAYMENT VERIFY — challenge carries the EXACT tier price; the
      //     signed authorization must commit to exactly that amount.
      if (oversizedPaymentHeader) {
        // R58: nothing will be dispatched, so release the reservation first.
        releaseReservation();
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
      v = await verifyPayment(env, request, {
        expectedAmount: tier.microUsdc,
        sizeBytes: file.size, // R46: price bound to the measured upload
        // R54: settlement is PART of verification — ok:true only after a
        // confirmed transfer AND a consumed nonce.
        settle: async (_payment, info) => {
          if (!cdpConfigured(env)) return { ok: false, reason: 'settlement_not_configured' };
          const hdrB64 = request.headers.get('PAYMENT-SIGNATURE')
            || request.headers.get('X-PAYMENT') || '';
          // R74: CLAIM FIRST. The DO reserve is atomic, so two concurrent
          // retries can never both reach the facilitator with one
          // authorization — the loser is rejected before any funds move.
          const claimNonce = (info && info.nonce) || v0Nonce;
          try { await consumeNonce(env, claimNonce); }
          catch (e) {
            console.error('[gateway] nonce claim rejected before settlement:', (e && e.message) || e);
            return { ok: false, reason: 'nonce_consumption_failed', terminal: false };
          }
          settleAttempted = true;
          const r = await cdpVerifyAndSettle(env, hdrB64,
            'csv-parquet-stream-compressor', tier.microUsdc, tier.microUsdc);
          if (r.ok !== true) {
            // Funds may or may not have moved: release the claim only when the
            // facilitator guarantees nothing was submitted, else keep it and
            // queue a refund.
            if (r.definitelyNotSubmitted === true) {
              try { await env.SECURITY_KV.delete('x402_nonce:' + claimNonce); } catch (_) {}
              return { ok: false, reason: r.reason, definitelyNotSubmitted: true };
            }
            return { ok: false, reason: r.reason, settledUnknown: r.settledUnknown,
              refundRequired: r.settledUnknown === true };
          }
          if (!/^0x[0-9a-fA-F]{64}$/.test(String(r.settledTx || ''))) {
            // R68: the facilitator said "paid" but gave no provable tx. Treat it
            // as TERMINAL and refundable — never a retryable "not paid".
            console.error('[gateway] settle ok but tx unproven', v0Nonce);
            return { ok: false, reason: 'settle_tx_unproven', terminal: true, refundable: true };
          }
                    return { ok: true, settledTx: r.settledTx, settledFrom: r.settledFrom,
            settledTo: r.settledTo, settledAmountUsdc: r.settledAmountUsdc,
            settledNonce: r.settledNonce };
        },
        // R45: independent on-chain confirmation (payer/recipient/amount).
        confirm: async (txHash, expected) => {
          const rpc = env.BASE_RPC_ENDPOINT || 'https://mainnet.base.org';
          const call = async (method, params) => {
            const resp = await fetch(rpc, { method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
            const j = await resp.json().catch(() => null);
            return j && j.result !== undefined ? j.result : null;
          };
          const receipt = await call('eth_getTransactionReceipt', [txHash]);
          if (!receipt || receipt.status !== '0x1') return { confirmed: false };
          const USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
          const TRANSFER = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
          const addr = (t) => '0x' + String(t).replace(/^0x/, '').slice(-40);
          for (const log of receipt.logs || []) {
            if (!log || !log.topics || !log.topics[0]) continue;
            if (String(log.topics[0]).toLowerCase() !== TRANSFER) continue;
            if (String(log.address || '').toLowerCase() !== USDC) continue;
            if (addr(log.topics[1]).toLowerCase() !== String(expected.from).toLowerCase()) continue;
            if (addr(log.topics[2]).toLowerCase() !== String(expected.to).toLowerCase()) continue;
            let amount; try { amount = BigInt(log.data || '0x0'); } catch (e) { continue; }
            if (amount < BigInt(expected.value)) continue;
            return { confirmed: true };
          }
          return { confirmed: false };
        },
      });
      if (!v.ok) {
        if (v.refundRequired || v.refundable) {
          // R70: payment was taken but settlement failed terminally — refund now.
          const refunded = await recordRefund(v.reason || 'settlement_terminal_failure');
          paymentSettled = true;              // funds were collected
          return json({ error: 'settlement_failed', reason: v.reason,
            refund: refunded ? 'completed' : 'queued',
            support: 'quote the nonce for support if the refund is queued' }, 502);
        }
        releaseReservation();   // R58: nothing paid, release the reservation
        return v.failResponse;
      }
      // v.ok:true means the transfer settled AND the nonce was consumed
      // (verifyPayment refuses to return ok without both).
      paymentSettled = true;

      // (9) UPSTREAM DISPATCH — build the outbound form and the timeout/
      //     disconnect wiring the fetch below depends on.
      const uploadName = safeName.endsWith('.parquet')
        ? safeName.slice(0, -'.parquet'.length).replace(/\.(csv|tsv|txt)$/i, '') +
          (fname.match(/\.(csv|tsv|txt)$/) || ['.csv'])[0]
        : safeName;
      const outForm = new FormData();
      outForm.append('file', new File([file], uploadName), uploadName);
      if (dest && dest.endpoint_url) outForm.append('target_destination', JSON.stringify(dest));

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(),
        tier.requiresUserDest ? 45 * 60 * 1000 : 10 * 60 * 1000);
      const onAbort = () => controller.abort();
      if (request.signal) {
        if (request.signal.aborted) controller.abort();
        else request.signal.addEventListener('abort', onAbort, { once: true });
      }

      upstreamDispatched = true;
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
                // R55: a settled payment has been COLLECTED — never release its claim.
        // Only an unsettled, undispatched claim may be released.
        if (env.CONSUMED_TX_STORE && v && v.nonce && !paymentSettled && !upstreamDispatched) {
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
                const refunded = await recordRefund('gateway_timeout');
                return json({ error: 'gateway_timeout', refund: refunded ? 'completed' : 'queued' }, 504);
              }
              // R24 + OX-ALPHA: only a genuine network drop that occurs before
              // RunPod accepted (upstream_unreachable) guarantees no compute was
              // bought — RELEASE the reservation by reconciling actual cost as $0.
              // (reconcile stays on THIS path ONLY.)
              // OX-ALPHA (FIX-3): unified ':reconcile' key on ALL reconciles.
              // R56: dispatch was ATTEMPTED — compute may have started, so
              // reconcile to the reserved estimate, never $0.
              ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', est).catch(() => {}))
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        // R55: a settled payment has been COLLECTED — never release its claim.
        // Only an unsettled, undispatched claim may be released.
        if (env.CONSUMED_TX_STORE && v && v.nonce && !paymentSettled && !upstreamDispatched) {
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
              const refundedU = await recordRefund('upstream_unreachable');
                return json({ error: 'upstream_unreachable', refund: refundedU ? 'completed' : 'queued' }, 502);
            }
      clearTimeout(timeoutId);
      if (request.signal) request.signal.removeEventListener('abort', onAbort);

      if (!upstream.ok) {
        // R77: a non-2xx does NOT prove the job never started — RunPod can
        // accept, run, then fail. Reconcile the ESTIMATE (conservative billing)
        // rather than $0, and refund the payer for the undelivered output.
        ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', est).catch(() => {}));
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        // R55: a settled payment has been COLLECTED — never release its claim.
        // Only an unsettled, undispatched claim may be released.
        if (env.CONSUMED_TX_STORE && v && v.nonce && !paymentSettled && !upstreamDispatched) {
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
        const refundedE = await recordRefund('upstream_error');
        return json({ error: 'upstream_error', upstream_status: upstream.status, refund: refundedE ? 'completed' : 'queued' }, 502);
      }
      const text = await upstream.text();
      let parsed;
      try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
      if (!parsed || typeof parsed !== 'object') {
        // R79: a non-JSON body does NOT prove no compute ran — the engine may
        // have accepted the job and failed while reporting. Reconcile the
        // ESTIMATE (conservative) rather than $0.
        ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', est).catch(() => {}));
        // R25: release the pre-dispatch nonce claim — no compute was bought/delivered.
        // R55: a settled payment has been COLLECTED — never release its claim.
        // Only an unsettled, undispatched claim may be released.
        if (env.CONSUMED_TX_STORE && v && v.nonce && !paymentSettled && !upstreamDispatched) {
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
        const refundedE = await recordRefund('upstream_error');
        return json({ error: 'upstream_error', upstream_status: upstream.status, refund: refundedE ? 'completed' : 'queued' }, 502);
      }
      const ALLOWED = ['status','output_bucket','output_key','rows','skipped_columns','skipped_rows','drift_fallback','duration_s','estimated_cost_usd','warning'];
      const body = {};
      // R80: validate each relayed field — bounded strings, no credential-looking
      // values, so a compromised engine cannot leak secrets through us.
      const SECRETS = /(?:AKIA|ASIA|sk[-_]|secret|passwd|password|token|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)/i;
      const cleanStr = (v, max = 300) => {
        if (typeof v !== 'string') return undefined;
        // Reject anything query-bearing or credential-like BEFORE truncation,
        // so a signed URL cannot be smuggled through.
        if (/[?&]/.test(v) || /%3f|%26/i.test(v)) return '[redacted-url]';
        if (SECRETS.test(v)) return '[redacted]';
        if (v.length > max) return v.slice(0, max) + '…';
        return v;
      };
      // Structured identifiers (bucket/key) must look like plain object paths.
      const plainPath = (v, max = 300) => {
        if (typeof v !== 'string') return undefined;
        if (!/^[A-Za-z0-9._\-/:]{1,200}$/.test(v)) return '[invalid]';
        return v.slice(0, max);
      };
      for (const k of ALLOWED) {
        if (parsed[k] === undefined) continue;
        if (typeof parsed[k] === 'string') {
          body[k] = (k === 'output_bucket' || k === 'output_key')
            ? plainPath(parsed[k])
            : cleanStr(parsed[k], k === 'warning' ? 200 : 120);
        } else if (typeof parsed[k] === 'number' && Number.isFinite(parsed[k])) {
          body[k] = parsed[k];
        } else if (k === 'skipped_columns' && Array.isArray(parsed[k])) {
          body[k] = parsed[k].slice(0, 100).map((c) => cleanStr(c, 80)).filter(Boolean);
        }
      }
      // R64: do NOT relay the engine's presigned download_url — the signed
      // query string IS a bearer credential. Advertise the controlled endpoint.
      if (parsed.download_url) body.download_via = '/v1/compress/result?ref=' + encodeURIComponent(JSON.stringify({
        key: parsed.output_key, bucket: parsed.output_bucket }));
      if (v && v.settledTx) body.settled_tx = v.settledTx;
      else if (v && v.settlePending) body.settle_pending = true;
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
      // R34 FINALIZE: the gate-8 reservation is now made permanent by
      // consumeNonce (DO atomic finalize, or a validBefore-aware KV marker).
      // Failure here is fatal — a nonce that can't be burned means this
      // authorization may be replayed, so we must not hand back the output.
      {
        try {
          await consumeNonce(env, v.nonce, v.validBefore);
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
      // R26c/R29: release nonce claim AND reconcile budget reservation on errors.
      try {
        if (typeof budgetTxId === 'string' && budgetTxId && !upstreamDispatched) {
          ctx.waitUntil(reconcileDailyBudget(env, budgetTxId + ':reconcile', 0).catch(() => {}));
        }
      } catch (_) {}
      let refundFail = false;
      let refundQueued = false;
      try {
        // R84: only refund when we KNOW funds moved. `settleAttempted`
        // means the facilitator was called (outcome unknown -> queue a
        // refund) while `v === null` with no attempt means nothing happened.
        if (!paymentSettled && settleAttempted) paymentSettled = true;
        if (paymentSettled && v && v.nonce) {
          // R65/R67: the payer paid and got nothing. A refund MUST be durably
          // recorded; if that fails we report 'required' so the operator
          // incident is explicit rather than a silent promise.
          const ok = await recordRefund('internal_error_after_settlement');
          refundFail = !ok;
          refundQueued = ok;
          if (refundFail) {
            console.error('[gateway] CRITICAL refund not recorded for', v.nonce,
              '— operator action required');
          }
        }
        // R55: a settled payment was COLLECTED — never release it.
        if (env.CONSUMED_TX_STORE && v && v.nonce && !paymentSettled && !upstreamDispatched) {
          const id2 = env.CONSUMED_TX_STORE.idFromName('singleton');
          const stub2 = env.CONSUMED_TX_STORE.get(id2);
          await stub2.fetch('https://internal/release-nonce', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nonce: v.nonce }) });
        }
      } catch (_) {}
      console.error('[gateway] internal_error:', (e && e.stack) || e);
      return json({ error: 'internal_error',
        refund: paymentSettled ? (refundQueued ? 'queued' : 'required') : undefined }, 500);
    }
  },
};
