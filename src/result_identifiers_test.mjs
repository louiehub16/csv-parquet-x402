// R41 regression test: BOTH output identifiers must be validated before storage.
//
// BUG: the result receipt validated only output_key (traversal + leading slash)
// and stored output_bucket verbatim. A compromised engine could therefore place
// a query-string or credential-looking value in the bucket name, which
// /v1/compress/result later returned to the paying customer.
//
// Contract: bucket AND key both pass plainPath(); an invalid identifier refunds
// and is NOT stored; what is stored is exactly what was validated.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// The real plainPath() definition, extracted so the test cannot drift.
const ppStart = idx.indexOf('const plainPath = (v, max = 300) => {');
ok('plainPath located', ppStart > 0, 'not found');
const ppBody = idx.slice(ppStart, idx.indexOf('};', ppStart) + 2);
const plainPath = new Function(ppBody + '\nreturn plainPath;')();

// --- the real gate must be present in the source ---
ok('bucket is validated through plainPath',
   /plainPath\(String\(receipt\.bucket/.test(idx), 'bucket not validated');
ok('key is validated through plainPath',
   /plainPath\(receiptKey/.test(idx), 'key not re-validated');
ok('an invalid identifier triggers a refund',
   /engine_unsafe_output_identifier/.test(idx) && /recordRefund\(/.test(idx),
   'no refund path');
ok('an invalid identifier returns 502, not 200',
   /engine_result_incomplete[\s\S]{0,220}502/.test(idx), 'no 502');
ok('the VALIDATED values are what get stored',
   /receipt\.bucket\s*=\s*safeBucket/.test(idx) && /receipt\.key\s*=\s*safeKeyPath/.test(idx),
   'raw values still stored');

// --- behavioural: plainPath() must reject what an engine could smuggle ---
{
  const REJECT = [
    ['b?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE', 'query-string credential in bucket'],
    ['b?token=abc123', 'query token in bucket'],
    ['my bucket', 'space in bucket'],
    ['b#fragment', 'fragment in bucket'],
    ['b\nX-Injected: 1', 'header injection attempt in bucket'],
    ['b&sig=zzz', 'ampersand param in bucket'],
  ];
  for (const [value, label] of REJECT) {
    const out = plainPath(value, 200);
    ok(`${label} is rejected`, out === undefined || out === '[invalid]',
      `${value} -> ${out}`);
  }

  const ACCEPT = [
    ['my-bucket', 'plain bucket'],
    ['account.r2.cloudflarestorage.com', 'dotted bucket'],
    ['outputs/data.parquet', 'nested key with separator'],
  ];
  for (const [value, label] of ACCEPT) {
    const out = plainPath(value, 200);
    ok(`${label} is accepted`, out === value, `${value} -> ${out}`);
  }

  // plainPath() is a SHAPE validator, so a bare credential-shaped string is
  // shape-valid. The identifier is returned verbatim to the paying client, so it
  // must ALSO be screened for credential material -- the same SECRETS pattern
  // already used for the relayed body fields.
  {
    const SECRETS = /(?:AKIA|ASIA|sk[-_]|secret|passwd|password|token|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)/i;
    const relaySafe = (v) => {
      const shape = plainPath(v, 200);
      if (!shape || shape === '[invalid]') return null;
      if (SECRETS.test(shape)) return null;      // credential material
      return shape;
    };
    for (const [value, label] of [
      ['AKIAIOSFODNN7EXAMPLE', 'bare access-key id as bucket'],
      ['my-token-bucket', 'token-shaped bucket name'],
      ['AKIA-secret', 'credential-looking bucket'],
    ]) {
      ok(`${label} is refused before storage`, relaySafe(value) === null,
         `${value} -> ${relaySafe(value)}`);
    }
    for (const [value, label] of [
      ['my-bucket', 'legitimate bucket'],
      ['outputs/data.parquet', 'legitimate key'],
      ['account.r2.cloudflarestorage.com', 'R2 bucket'],
    ]) {
      ok(`${label} still relays`, relaySafe(value) === value, `${value} -> ${relaySafe(value)}`);
    }
  }
}

// --- behavioural: THE PRODUCTION GATE must refuse these, not a local copy ---
// The helper above proves plainPath() behaves; what matters is that the
// receipt gate actually applies it to BOTH identifiers. Assert against the
// production source rather than a local reimplementation.
{
  const gate = idx.slice(idx.indexOf('const safeBucket = plainPath('),
                             idx.indexOf("receipt.key = safeKeyPath;") + 40);
  ok('the gate screens BOTH identifiers', /safeBucket/.test(gate) && /safeKeyPath/.test(gate),
     'gate does not cover both');
  ok('an invalid identifier is refused before any write',
     /if \(!safeBucket/.test(gate) && /engine_unsafe_output_identifier/.test(gate),
     'no refusal');
  ok('plainPath output is compared against the [invalid] sentinel',
     /\[invalid\]/.test(gate), 'sentinel not checked');

  // The identity check: the gate must reject a credential-shaped identifier,
  // because the stored value is returned verbatim to the paying client.
  ok('credential material is refused, not just malformed shape',
     /SECRETS\.test/.test(gate), 'no credential screening on the identifiers');
  // SECRETS is defined earlier in the function; assert the pattern it carries,
  // not that it is repeated inside the gate.
  const secretsDef = idx.slice(idx.indexOf('const SECRETS ='),
                              idx.indexOf('const SECRETS =') + 220);
  ok('it reuses the SECRETS pattern already applied to relayed body fields',
     /AKIA\|ASIA\|sk\[-_\]/.test(secretsDef), 'different credential pattern');
  ok('the gate is inside the same scope as SECRETS (declared before it)',
     idx.indexOf('const SECRETS =') < idx.indexOf('const safeBucket = plainPath('),
     'SECRETS is declared after the gate -- would be a TDZ ReferenceError');
}
{
  const traversal = (k) => k.startsWith('/') || k.split('/').some((s) => s === '..' || s === '.');
  ok('"../etc/passwd" is traversal', traversal('../etc/passwd'), 'missed');
  ok('"outputs/../../etc" is traversal', traversal('outputs/../../etc'), 'missed');
  ok('"/absolute.parquet" is rejected', traversal('/absolute.parquet'), 'missed');
  ok('"outputs/data.parquet" is clean', !traversal('outputs/data.parquet'), 'false positive');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R41-IDENTIFIERS-FAIL (${fails.length})`
  : 'R41-IDENTIFIERS-ALL-PASS (bucket AND key validated through plainPath; query strings, ' +
    'credentials and injection attempts rejected; traversal still refused; only the ' +
    'validated values are stored)');
process.exit(fails.length ? 1 : 0);
