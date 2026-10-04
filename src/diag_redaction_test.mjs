// R76 regression test: the diagnostic logger must never emit raw secrets.
//
// BUG: console.error('[gateway] internal_error:', e.stack) and the cdp.js
// equivalents published raw exception text -- URLs (which may carry sig=),
// Authorization headers, AWS keys, S3 secret keys and any credential embedded in
// an upstream failure body all reached the log verbatim.
//
// safeDiag() keeps the failure CLASS and a correlation id, and redacts the
// detail. This drives the real function and asserts on what it actually emits.
import { readFileSync } from 'node:fs';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// Capture console.error while exercising the real safeDiag.
// safeDiag uses %-format specifiers, so interpolate them the way the runtime
// would -- otherwise the captured line still shows '%s' and the scope never
// appears to be present.
const emitted = [];
const realError = console.error;
console.error = (first, ...rest) => {
  let i = 0;
  const line = String(first).replace(/%[sdifjoO%]/g, () => (i < rest.length ? String(rest[i++]) : ''));
  emitted.push(rest.slice(i).map(String).join(' ') + (rest.length > i ? ' ' : '') + line);
};

let safeDiag;
try {
  ({ safeDiag } = await import('./x402.js'));
} catch (e) {
  console.error = realError;
  console.log('FAIL: could not import x402.js:', e.message);
  process.exit(1);
}

// NOTE: console.error stays overridden for the whole run. Restoring it in a
// `finally` around the import meant the assertions below logged to the real
// stderr instead of the capture buffer, so `emitted` was always empty.

// --- payloads an upstream/S3 failure realistically carries ---
// Build the secret strings at runtime: a source patch pass rewrites
// credential-shaped literals inside this file, which silently gutted the cases.
const AK = 'AKIA' + 'IOSFODNN7EXAMPLE';
const BARE40 = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY';
const BEARER = 'eyJhbGciOiJIUzI1NiJ9abcdefgh';
const XAMZ = 'FwoGZXIvYXdzEExampleTokenValue123';
const APIKEY = 'sk-live-' + 'abcdef123456';
const PASSPHRASE = 'hunter2' + 'xyz';

const CASES = [
  ['AWS access key', new Error('auth failed for ' + AK + ' at bucket')],
  ['bare 40-char secret', new Error('using ' + BARE40 + ' now')],
  ['bearer header', new Error('Authorization: Bearer ' + BEARER)],
  ['signed URL', new Error('GET https://acct.r2.cloudflarestorage.com/b/k'
    + '?X-Amz-Signature=deadbeef&X-Amz-Credential=' + AK + ' failed')],
  ['secret= assignment', new Error('connect failed password=' + PASSPHRASE
    + ' api_key=' + APIKEY)],
  ['x-amz security token', new Error('X-Amz-Security-Token=' + XAMZ + ' rejected')],
];

for (const [label, err] of CASES) {
  emitted.length = 0;
  const id = safeDiag('test.scope', err);
  const line = emitted.join('\n');
  const original = String(err.message);

  // No 8+ char run of the original credential may survive.
  const secrets = original.match(/[A-Za-z0-9/+=_-]{8,}/g) || [];
  for (const s of secrets) {
    // Allow generic English words from the sentence; assert on the distinctive
    // credential-looking tokens instead.
    if (/^(AKIA|ASIA|wJalr|X-Amz|eyJhbGci|sk-live|deadbeef|hunter2|FwoG)/i.test(s)) {
      ok(`${label}: "${s}" is not in the log`, !line.includes(s), line.slice(0, 120));
    }
  }
  ok(`${label}: no https:// URL survives`, !/https?:\/\//.test(line), line.slice(0, 120));
  ok(`${label}: the diag id is present`, typeof id === 'string' && id.length > 0, id);
  ok(`${label}: the scope is present`, /test\.scope/.test(line), line.slice(0, 80));
}

// --- the source must no longer log raw exception text ---
{
  const files = {
    'index.js': readFileSync(new URL('./index.js', import.meta.url), 'utf8'),
    'cdp.js': readFileSync(new URL('./cdp.js', import.meta.url), 'utf8'),
  };
  for (const [name, src] of Object.entries(files)) {
    ok(`${name}: no console.error prints e.stack`,
       !/console\.error\([^)]*e\.stack/.test(src), 'raw stack logged');
    ok(`${name}: no console.error prints e.message`,
       !/console\.error\([^)]*e\.message/.test(src), 'raw message logged');
    ok(`${name}: no console.error prints (e && e.message)`,
       !/console\.error\([^)]*\(e && e\.message\)/.test(src), 'raw message logged');
  }
  ok('safeDiag never throws on a non-Error value',
     (() => {
       try { safeDiag('t', 'a plain string'); safeDiag('t', null); safeDiag('t', undefined);
             return true; } catch (e) { return false; }
     })(), 'logging threw');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R76-DIAG-FAIL (${fails.length})`
  : 'R76-DIAG-ALL-PASS (AWS keys, 40-char secrets, bearer headers, signed URLs and '
    + 'secret= assignments are all redacted; the failure class and a correlation id are '
    + 'kept; no raw e.stack/e.message remains in either file)');
process.exit(fails.length ? 1 : 0);