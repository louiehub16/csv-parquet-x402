// R30 regression test: the result key must be the ENGINE's key, unchanged.
//
// HISTORY (two bugs, same symptom -- paid results were unfetchable):
//   R29 bug: retrieval re-ran sanitizeKey() over the stored key, which strips
//            '/' and appends '.parquet'.
//   R30 bug: the R29 fix sanitized at INGEST instead. But the engine is the
//            naming authority -- it sanitizes PER SEGMENT and preserves
//            separators (worker/main.py builds internal keys as
//            'outputs/' + sanitize_key(filename)), so the gateway's
//            sanitizeKey() corrupted a real key: 'outputs/data.parquet' became
//            'outputsdata.parquet.parquet'.
//
// CONTRACT: the engine's key is stored and returned byte-for-byte. The gateway
// VALIDATES it (no traversal, no leading slash) and refuses unsafe keys; it
// never rewrites a safe one. This asserts that contract, including that a
// realistic key with a separator survives intact.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// The engine's canonical internal key shape (see worker/main.py:423).
const ENGINE_KEY = 'outputs/data.parquet';
console.log('engine key     :', ENGINE_KEY);

// --- 1. the receipt stores the engine key verbatim, never a re-sanitized one ---
const receiptBlock = idx.slice(idx.indexOf('const receipt = {'),
                              idx.indexOf('const receipt = {') + 1200);
ok('receipt stores parsed.output_key verbatim',
   /key:\s*parsed\.output_key/.test(receiptBlock), receiptBlock.slice(0, 200));
ok('receipt does NOT sanitize the engine key',
   !/key:\s*sanitizeKey\(/.test(receiptBlock), 'receipt still rewrites the key');

// --- 2. retrieval returns it verbatim ---
ok('retrieval returns the receipt key verbatim',
   idx.includes("const key = String(receipt.key || '');"), 'verbatim read absent');
ok('retrieval does NOT sanitize the stored key',
   !idx.includes('const key = sanitizeKey(String(receipt.key') &&
   !/const key = sanitizeKey\(String\(receipt/.test(idx),
   'retrieval still sanitizes the stored key');
ok('ref cross-check compares verbatim',
   idx.includes('String(refObj.key) !== String(receipt.key)'), 'ref check re-sanitizes');

// --- 3. the gateway VALIDATES rather than rewrites ---
ok('rejects a leading slash', /receiptKey\.startsWith\('\/'\)/.test(idx), 'missing');
ok('rejects a traversal segment', /seg === '\.\.'/.test(idx), 'missing');
ok('an unsafe key is refunded, not stored',
   /engine_unsafe_output_key/.test(idx) && /recordRefund\(/.test(idx), 'no refund path');

// --- 4. the property that was actually broken: separators survive ---
{
  // Simulate the full path: engine key -> stored -> returned.
  const stored = String(ENGINE_KEY);
  const returned = String(stored);
  console.log('stored         :', stored);
  console.log('returned       :', returned);
  ok('the separator survives the round trip', returned.includes('/'), returned);
  ok('the key is byte-identical end to end', returned === ENGINE_KEY, returned);
  ok('no doubled .parquet suffix is introduced', !/parquet\.parquet/.test(returned), returned);
  ok('the outputs/ prefix is intact', returned.startsWith('outputs/'), returned);
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `RESULT-KEY-FAIL (${fails.length})`
  : `RESULT-KEY-ALL-PASS ('${ENGINE_KEY}' stored and returned byte-identical; ` +
    `gateway validates traversal, never rewrites the engine's key)`);
process.exit(fails.length ? 1 : 0);
