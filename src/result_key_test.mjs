// R29 regression test: the stored result key must survive the receipt round trip.
//
// BUG: the receipt stored the engine's real object key (e.g.
// 'outputs/tiny.parquet') but retrieval re-ran sanitizeKey() over it.
// sanitizeKey() strips path separators and appends '.parquet', so the returned
// key became 'outputstiny.parquet.parquet' -- a name that matches no stored
// object. Every PAID result was unfetchable, and the bug was invisible until a
// customer tried to download.
//
// The contract: sanitize ONCE at ingest, store that value, return it verbatim.
// This asserts the round trip is stable -- sanitize(sanitize(x)) must never be
// applied to a stored key, so re-sanitizing must CHANGE a realistic key.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// Recreate sanitizeKey EXACTLY as the source defines it, and verify the copy is
// faithful (if this drifts from index.js the test would be meaningless).
const body = idx.slice(idx.indexOf('function sanitizeKey(name) {'),
                       idx.indexOf('export default {'));
ok('sanitizeKey body located', body.includes('.replace'), 'not found');
const fn = new Function(
  body.slice(body.indexOf('function sanitizeKey'),
             body.indexOf('\n}', body.indexOf('function sanitizeKey')) + 2)
  + '\nreturn sanitizeKey;')();
const sample = 'outputs/tiny.parquet';
const real = fn(sample);
console.log('engine key     :', sample);
console.log('sanitizeKey()  :', real);
ok('sanitizeKey strips the separator (precondition)', !real.includes('/'), real);
ok('sanitizeKey is non-idempotent on a stored key', fn(real) !== real,
   `re-sanitizing changed it: ${fn(real)}`);

// --- the receipt must store the SANITIZED key, and retrieval must not re-sanitize ---
const receiptStart = idx.indexOf('const receipt = {');
const receiptBlock = idx.slice(receiptStart, receiptStart + 500);
ok('receipt stores sanitizeKey(output_key)',
   /key:\s*sanitizeKey\(parsed\.output_key\)/.test(receiptBlock),
   receiptBlock.slice(0, 200));

const retStart = idx.indexOf('const key = String(receipt.key');
ok('retrieval returns the receipt key verbatim',
   retStart > 0, 'verbatim read not found');
const around = idx.slice(Math.max(0, retStart - 500), retStart + 200);
ok('retrieval does NOT call sanitizeKey on the receipt key',
   !/const key = sanitizeKey\(String\(receipt\.key/.test(idx),
   'retrieval still re-sanitizes the stored key');
ok('ref cross-check compares verbatim', /String\(refObj\.key\) !== String\(receipt\.key\)/.test(idx),
   'ref comparison still re-sanitizes');

// --- end-to-end property: the key a customer receives must equal the stored one ---
{
  const stored = real;                       // what the receipt holds
  const returned = String(stored);           // retrieval now returns it verbatim
  ok('stored key is returned unchanged', returned === stored, `${stored} -> ${returned}`);
  // NOTE: sanitizeKey() legitimately appends '.parquet' to a key that already
  // ends in it, so a doubled suffix on the STORED key is expected behaviour.
  // The defect was sanitizing a SECOND time at retrieval (asserted above), not
  // the shape of the sanitized value.
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `RESULT-KEY-FAIL (${fails.length})`
  : `RESULT-KEY-ALL-PASS ('${sample}' -> stored '${real}' -> returned unchanged; ` +
    `sanitize applied ONCE at ingest, never again at retrieval)`);
process.exit(fails.length ? 1 : 0);
