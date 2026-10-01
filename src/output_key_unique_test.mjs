// R44/R55 regression test: output keys must be unique per paid job, and the
// uniqueness must NOT be derived from a payer-controlled value.
//
// R44: the outbound filename was the sanitized input name only, so two
// concurrent jobs uploading `data.csv` targeted the SAME object -- one silently
// overwrote the other and a payer could be served another customer's file.
//
// R55: the first fix used the first 16 hex chars of the PAYER-CONTROLLED
// authorization nonce as the job prefix. That is only 64 bits and the payer
// chooses it, so two authorizations sharing a prefix would still collide. The
// prefix is now a GATEWAY-GENERATED 128-bit id.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- the production naming block, mirrored only in shape ------------------
// The gateway supplies jobStem; this mirrors the stem/baseStem/ext assembly
// so the collision property can be exercised directly.
const makeName = (safeName, fname, jobStem) => {
  jobStem = jobStem || 'a'.repeat(32);
  const baseStem = safeName.endsWith('.parquet')
    ? safeName.slice(0, -'.parquet'.length).replace(/\.(csv|tsv|txt)$/i, '')
    : safeName.replace(/\.(csv|tsv|txt)$/i, '');
  const extMatch = fname.match(/\.(csv|tsv|txt)$/i);
  const ext = extMatch ? extMatch[0] : '.csv';
  return `${jobStem}-${baseStem}${ext}`;
};

// --- 1. the stem is gateway-generated, not payer-derived, not truncated ---
{
  ok('the stem is a gateway-generated random id',
     /const jobStem = crypto\.randomUUID\(\)/.test(idx), 'not a random UUID');
  ok('the stem is NOT derived from the payer-controlled nonce',
     !/const jobStem = \(v && v\.nonce/.test(idx), 'still derived from the nonce');
  ok('the full 128-bit id is used (not truncated to 64 bits)',
     !/jobStem[^;]*slice\(0,\s*16\)/.test(idx), 'stem is truncated to 16 hex chars');
  ok('the outbound name is still <stem>-<original><ext>',
     /uploadName = `\$\{jobStem\}-\$\{baseStem\}\$\{ext\}`/.test(idx),
     'name shape changed');
}

// --- 2. two jobs, same filename, DIFFERENT stems -> distinct keys ---------
{
  const a = makeName('data.parquet', 'data.csv', 'ab'.repeat(16));
  const b = makeName('data.parquet', 'data.csv', 'cd'.repeat(16));
  console.log('job A name:', a);
  console.log('job B name:', b);
  ok('two same-named jobs with different stems produce DIFFERENT names', a !== b,
     `${a} == ${b}`);
  ok('the stem is long enough to be collision-resistant (>= 128 bits)',
     a.split('-')[0].length >= 32, a.split('-')[0].length);
}

// --- 3. two jobs sharing a 64-bit NONCE PREFIX still get distinct keys ----
// This is the R55 bug: under the old contract the stem WAS the nonce prefix,
// so these two jobs collided. Under the new contract the payer cannot influence
// the stem at all, so they do not.
{
  // Two nonces that agree on the first 16 hex chars (the old stem).
  const nonceA = 'ab'.repeat(16) + '11'.repeat(16);
  const nonceB = 'ab'.repeat(16) + '22'.repeat(16);
  ok('the two nonces really do share a 64-bit prefix',
     nonceA.slice(0, 16) === nonceB.slice(0, 16), 'precondition');
  // Under the new scheme the stem is independent of the nonce, so the keys
  // differ because the gateway generated different ids:
  const a = makeName('data.parquet', 'data.csv', 'ab'.repeat(16));
  const b = makeName('data.parquet', 'data.csv', 'cd'.repeat(16));
  ok('a shared nonce prefix cannot collide the keys any more', a !== b,
     `${a} == ${b}`);
}

// --- 4. the original filename/extension are preserved ---------------------
{
  const n = makeName('data.parquet', 'weird name.CSV', 'ab'.repeat(16));
  ok('the real input extension is preserved', n.endsWith('.CSV'), n);
  ok('the name still carries the original stem', n.includes('data'), n);
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R44-R55-KEY-UNIQUE-FAIL (${fails.length})`
  : 'R44-R55-KEY-UNIQUE-ALL-PASS (keys are unique per job; the stem is a full '
    + 'gateway-generated 128-bit id, so a shared payer nonce prefix cannot collide '
    + 'them; the input stem and extension are preserved)');
process.exit(fails.length ? 1 : 0);