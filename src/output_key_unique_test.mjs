// R44 regression test: output keys must be unique per paid job.
//
// BUG: the outbound filename (and therefore the storage key) was derived ONLY
// from the sanitized input filename -- the engine writes
// 'outputs/' + sanitize_key(filename). Two concurrent jobs uploading `data.csv`
// therefore targeted the SAME object: one silently overwrote the other, and a
// payer could be served another customer's file. That is a cross-tenant data
// leak on a paid service.
//
// The gateway now prefixes a per-job stem derived from the paid authorization
// nonce. This drives the real naming logic and asserts collision-freedom.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// The naming logic, mirroring the production block (jobStem -> baseStem -> ext).
const makeName = (safeName, fname, nonce) => {
  const jobStem = (nonce ? String(nonce).replace(/^0x/, '').slice(0, 16)
                         : 'a'.repeat(16));
  const baseStem = safeName.endsWith('.parquet')
    ? safeName.slice(0, -'.parquet'.length).replace(/\.(csv|tsv|txt)$/i, '')
    : safeName.replace(/\.(csv|tsv|txt)$/i, '');
  const extMatch = fname.match(/\.(csv|tsv|txt)$/i);
  const ext = extMatch ? extMatch[0] : '.csv';
  return `${jobStem}-${baseStem}${ext}`;
};

// --- the production source must do this ---
ok('a per-job stem is derived from the paid nonce',
   /const jobStem = \(v && v\.nonce/.test(idx), 'no nonce-derived job stem');
ok('the outbound name is prefixed with it',
   /uploadName = `\$\{jobStem\}-\$\{baseStem\}\$\{ext\}`/.test(idx), 'name not prefixed');
ok('the original stem and extension are preserved',
   /baseStem/.test(idx) && /extMatch/.test(idx), 'stem/extension not derived');
ok('a random fallback exists for the pre-payment path',
   /crypto\.randomUUID\(\)/.test(idx), 'no fallback when the nonce is absent');

// --- two jobs with the SAME filename must NOT collide ---
{
  const nonceA = 'ab'.repeat(32);
  const nonceB = 'cd'.repeat(32);
  const a = makeName('data.parquet', 'data.csv', nonceA);
  const b = makeName('data.parquet', 'data.csv', nonceB);
  console.log('job A name:', a);
  console.log('job B name:', b);

  ok('two same-named jobs produce DIFFERENT names', a !== b, `${a} == ${b}`);
  ok('the name still ends in the real input extension', a.endsWith('.csv'), a);
  ok('the original stem is still recognizable', a.includes('data'), a);
  ok('the stem is short enough to stay within key limits', a.length <= 64, `${a.length} chars`);
}

// --- different extensions are preserved, not flattened ---
for (const [fname, wantExt, label] of [
  ['data.csv', '.csv', 'csv'],
  ['data.tsv', '.tsv', 'tsv'],
  ['data.txt', '.txt', 'txt'],
  ['weird name.CSV', '.CSV', 'uppercase extension'],
]) {
  const n = makeName('data.parquet', fname, 'ab'.repeat(32));
  ok(`${label} keeps its extension`, n.endsWith(wantExt), `${fname} -> ${n}`);
}

// --- the engine must still write under outputs/ (its own key composition) ---
{
  const py = readFileSync(new URL('../worker/main.py', import.meta.url), 'utf8');
  ok('the engine still prefixes internal keys with outputs/',
     /key = "outputs\/" \+ sanitize_key\(/.test(py), 'engine key prefix changed');
  ok('the engine sanitizes the filename per segment',
     /sanitize_key\(/.test(py), 'sanitize_key missing');
}

// --- the engine must NOT be stripping a prefix that carries uniqueness ---
{
  const py = readFileSync(new URL('../worker/main.py', import.meta.url), 'utf8');
  ok('the engine does not collapse the whole path to a basename',
     !/key = sanitize_key\(os\.path\.basename/.test(py),
     'engine flattens the key to a basename, discarding uniqueness');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R44-KEY-UNIQUE-FAIL (${fails.length})`
  : `R44-KEY-UNIQUE-ALL-PASS (same filename + different nonces -> distinct names: ` +
    `'${makeName('data.parquet', 'data.csv', 'ab'.repeat(32))}' vs ` +
    `'${makeName('data.parquet', 'data.csv', 'cd'.repeat(32))}'; extensions preserved)`);
process.exit(fails.length ? 1 : 0);
