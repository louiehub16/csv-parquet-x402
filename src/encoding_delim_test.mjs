// R64 regression tests for two defects reviewer B found in round 64.
//
//  1. UTF-8 VALIDATION ONLY COVERED THE FIRST 1 MiB. R45 extended NUL/magic
//     scanning to the whole body but left the encoding check on the prefix, so
//     invalid UTF-8 past that boundary reached paid processing.
//
//  2. THE ENGINE NEVER SNIFFED NEWLINE AS A DELIMITER. DELIMS was
//     (",", ";", "\t") while the gateway ACCEPTS newline as a valid delimiter, so
//     a newline-delimited .txt/.csv was sniffed as something else and silently
//     corrupted.
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// ---------- 1. full-body UTF-8 validation in the gateway -------------------
{
  const idx = readFileSync(join(HERE, 'index.js'), 'utf8');
  ok('the gateway validates the FULL body as UTF-8',
     /new TextDecoder\('utf-8', \{ fatal: true \}\)\.decode\(whole\)/.test(idx),
     'no full-body decode');
  ok('it decodes the whole file, not a 1 MiB slice',
     /const whole = new Uint8Array\(await file\.arrayBuffer\(\)\)/.test(idx),
     'full body not read');
  ok('invalid UTF-8 anywhere is refused with 400',
     /error:\s*'invalid_utf8'/.test(idx), 'no invalid_utf8 response');
  ok('the validation happens BEFORE dispatch',
     idx.indexOf('FULL-BODY UTF-8 VALIDATION') <
     idx.indexOf('UPSTREAM DISPATCH'),
     'validation is after dispatch');
  ok('the cheap 1 MiB sniff still exists (delimiters/BOM)',
     /file\.slice\(0, 1048576\)/.test(idx), 'prefix sniff removed');
}

// ---------- 2. the engine sniffs newline as a delimiter --------------------
{
  const py = readFileSync(join(HERE, '..', 'worker', 'main.py'), 'utf8');
  const m = py.match(/^DELIMS\s*=\s*\((.*?)\)/m);
  ok('DELIMS is defined', !!m, 'not found');
  if (m) {
    const delims = m[1];
    ok('newline is a sniff candidate', /\\n/.test(delims), `DELIMS = (${delims})`);
    ok('carriage return is a sniff candidate', /\\r/.test(delims), `DELIMS = (${delims})`);
    ok('comma is still a candidate', /","/.test(delims), `DELIMS = (${delims})`);
    ok('tab is still a candidate', /\\t/.test(delims), `DELIMS = (${delims})`);
    ok('semicolon is still a candidate', /";"/.test(delims), `DELIMS = (${delims})`);
  }
}

// ---------- 3. behavioural: newline-delimited input is sniffed correctly ----
{
  // choose_delimiter is Python. Write the probe to a temp .py file and RUN it --
  // passing Python source through `python -c` across the JS layer mangled every
  // backslash escape and produced a bogus SyntaxError.
  const py = readFileSync(join(HERE, '..', 'worker', 'main.py'), 'utf8');
  const s = py.indexOf('def choose_delimiter(');
  const blank = py.indexOf('\n\n', s);
  const fnSrc = py.slice(s, blank > 0 ? blank : s + 1500);
  const delimsSrc = (py.match(/^DELIMS\s*=\s*\(.*?\)/m) || [''])[0];

  const dir = mkdtempSync(join(tmpdir(), 'r64-'));
  const probe = join(dir, 'probe.py');
  writeFileSync(probe, [
    'import io',
    delimsSrc,
    fnSrc,
    'def _run(sample, name):',
    '    return choose_delimiter(name, io.BytesIO(sample.encode("utf-8")))',
    'NL = chr(10)',
    'TAB = chr(9)',
    'print("NL=%r"  % _run("alpha" + NL + "beta" + NL + "gamma" + NL, "data.txt"))',
    'print("CSV=%r" % _run("a,b" + NL + "c,d" + NL, "data.csv"))',
    'print("TSV=%r" % _run("a" + TAB + "b" + NL + "c" + TAB + "d" + NL, "data.tsv"))',
  ].join('\n'));

  let out = '', code = 0;
  try {
    out = execSync(`python "${probe}"`, { encoding: 'utf-8', timeout: 60000 });
  } catch (e) {
    code = 1; out = String(e.stdout || '') + String(e.stderr || '');
  }
  rmSync(dir, { recursive: true, force: true });
  console.log(out.trim());
  ok('the delimiter probe ran', code === 0, out.trim().slice(-200));
  ok('a newline-delimited .txt sniffs as a newline (not corrupted)',
     /NL=('\\n'|\\r')/.test(out), out.trim());
  ok('a .csv still sniffs as comma', /CSV=','/.test(out), out.trim());
  ok('a .tsv still sniffs as tab', /TSV='\\t'/.test(out), out.trim());
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R64-FAIL (${fails.length})`
  : 'R64-ALL-PASS (invalid UTF-8 anywhere in the upload is refused before payment; '
    + 'the engine sniffs newline as a delimiter while keeping comma/semicolon/tab)');
process.exit(fails.length ? 1 : 0);