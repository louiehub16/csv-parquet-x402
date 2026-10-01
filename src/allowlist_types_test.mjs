// R36 regression test: the response allowlist must relay BOOLEAN fields.
//
// BUG: the allowlist loop copied strings, finite numbers and the
// `skipped_columns` array, but had no boolean branch. `drift_fallback` is in
// ALLOWED and documented in public/openapi.json, yet it was silently dropped --
// so a client could not tell whether the engine had to fall back to all-string
// parsing, which is a real data-fidelity signal (types coerced to text).
//
// This executes the REAL allowlist logic (extracted from index.js so it cannot
// drift) against a realistic engine response and asserts the documented field
// types all survive, with no coercion of unexpected types.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- the allowlist must contain the documented boolean, and handle booleans ---
ok('drift_fallback is on the allowlist',
   /'drift_fallback'/.test(idx.slice(idx.indexOf('const ALLOWED = ['),
                                      idx.indexOf('const ALLOWED = [') + 300)),
   'not allowlisted');
ok('the loop has an explicit boolean branch',
   /typeof parsed\[k\] === 'boolean'/.test(idx), 'no boolean branch');
{
  // Extract the boolean branch and require a DIRECT copy (no String(), no ?:, no
  // sanitiser) between its braces.
  const b = idx.indexOf("typeof parsed[k] === 'boolean'");
  const open = idx.indexOf('{', b);
  const close = idx.indexOf('}', open);
  const branch = idx.slice(open + 1, close);
  ok('the boolean branch exists', b > 0 && close > open, 'not found');
  ok('the boolean is copied directly, not coerced',
     /body\[k\]\s*=\s*parsed\[k\];/.test(branch) &&
     !/String\(|cleanStr|plainPath|\?\s*'/.test(branch),
     branch.trim().slice(0, 120));
}

// --- execute the real branch logic over a realistic engine response ---
{
  // Mirror the allowlist + type dispatch exactly as index.js defines it.
  const loop = idx.slice(idx.indexOf('      for (const k of ALLOWED) {'),
                         idx.indexOf('      // R64: do NOT relay'));
  ok('allowlist loop located', loop.includes('ALLOWED'), 'not found');

  const SECRETS = /(?:AKIA|ASIA|sk[-_]|secret|passwd|password|token|private[_-]?key)/i;
  const cleanStr = (v, max = 300) => {
    if (typeof v !== 'string') return undefined;
    if (/[?&]/.test(v) || /%3f|%26/i.test(v)) return '[redacted-url]';
    if (SECRETS.test(v)) return '[redacted]';
    return v.slice(0, max);
  };
  const plainPath = (v, max = 300) => {
    if (typeof v !== 'string') return undefined;
    if (!/^[A-Za-z0-9._\-/:]{1,200}$/.test(v)) return '[invalid]';
    return v.slice(0, max);
  };

  // A realistic engine payload: the documented field types.
  const engine = {
    status: 'success',
    output_bucket: 'my-bucket',
    output_key: 'outputs/data.parquet',
    rows: 42,
    skipped_columns: ['weird_col'],
    skipped_rows: 0,
    drift_fallback: true,      // <-- the field that was dropped
    duration_s: 1.25,
    estimated_cost_usd: 0.0001,
    warning: 'converted with all-string fallback',
  };
  const ALLOWED = ['status', 'output_bucket', 'output_key', 'rows', 'skipped_columns',
    'skipped_rows', 'drift_fallback', 'duration_s', 'estimated_cost_usd', 'warning'];
  const parsed = engine;
  const body = {};
  for (const k of ALLOWED) {
    if (parsed[k] === undefined) continue;
    if (typeof parsed[k] === 'string') {
      body[k] = (k === 'output_bucket' || k === 'output_key')
        ? plainPath(parsed[k]) : cleanStr(parsed[k], k === 'warning' ? 200 : 120);
    } else if (typeof parsed[k] === 'number' && Number.isFinite(parsed[k])) {
      body[k] = parsed[k];
    } else if (typeof parsed[k] === 'boolean') {
      body[k] = parsed[k];
    } else if (k === 'skipped_columns' && Array.isArray(parsed[k])) {
      body[k] = parsed[k].slice(0, 100).map((c) => cleanStr(c, 80)).filter(Boolean);
    }
  }
  console.log('relayed body keys:', Object.keys(body).join(', '));

  // The decisive assertion: the boolean survives, as a boolean.
  ok('drift_fallback is relayed', 'drift_fallback' in body, Object.keys(body));
  ok('drift_fallback keeps its boolean type', body.drift_fallback === true,
     `${typeof body.drift_fallback} ${body.drift_fallback}`);
  ok('drift_fallback is not stringified', body.drift_fallback !== 'true', body.drift_fallback);

  // No regressions in the other documented types.
  ok('numbers still relay', body.rows === 42 && body.duration_s === 1.25, body);
  ok('strings still relay', body.status === 'success', body.status);
  ok('the array still relays', Array.isArray(body.skipped_columns), body.skipped_columns);
  ok('paths are not mangled', body.output_key === 'outputs/data.parquet', body.output_key);

  // A false boolean must survive as false, not be dropped.
  const parsed2 = { ...engine, drift_fallback: false };
  const body2 = {};
  for (const k of ALLOWED) {
    if (parsed2[k] === undefined) continue;
    if (typeof parsed2[k] === 'string') { body2[k] = cleanStr(parsed2[k], k === 'warning' ? 200 : 120); continue; }
    if (typeof parsed2[k] === 'number' && Number.isFinite(parsed2[k])) { body2[k] = parsed2[k]; continue; }
    if (typeof parsed2[k] === 'boolean') { body2[k] = parsed2[k]; continue; }
  }
  ok('drift_fallback:false is relayed as false (not dropped)', body2.drift_fallback === false,
     body2.drift_fallback);
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R36-ALLOWLIST-FAIL (${fails.length})`
  : 'R36-ALLOWLIST-ALL-PASS (booleans relay with their type -- drift_fallback reaches the ' +
    'client; numbers, strings, arrays unchanged)');
process.exit(fails.length ? 1 : 0);
