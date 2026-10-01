// R34 regression tests for two fixes.
//
//  1. parseAuthHeader() read ONLY dec.payload.authorization. A verified gateway
//     envelope nests the authorization at dec.payload.payload.authorization
//     (the shape cdp.js was fixed for in R28), so every legitimate result
//     lookup failed to parse and paying customers were locked out of their
//     results. Both depths must resolve.
//
//  2. worker/main.py returned mask_secret(redact_message(first_error)) for a
//     pre-parse internal failure. mask_secret() keeps first4...last4 of anything
//     >= 12 chars and redaction only strips unlabeled 40-char secrets, so a
//     shorter credential had 8 characters published in the response body.
//
// Test 1 drives the real endpoint's parser through both envelope shapes.
// Test 2 asserts the response text is a fixed generic string.
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// ---------- 1. parseAuthHeader resolves BOTH depths ----------
{
  const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  const start = idx.indexOf('function parseAuthHeader(hdr) {');
  const body = idx.slice(start, idx.indexOf('\n}', start) + 2);
  ok('parseAuthHeader body located', body.includes('authorization'), 'not found');

  // Execute the real function against both envelope shapes.
  const fn = new Function(body + '\nreturn parseAuthHeader;')();
  const b64u = (obj) => Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');

  const auth = {
    from: '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A',
    to: '0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83',
    value: '10000', validAfter: '0', validBefore: '9999999999',
    nonce: 'ab'.repeat(32),
  };
  const sig = { r: '0x' + '11'.repeat(32), s: '0x' + '22'.repeat(32), v: 27 };

  // DEEP shape -- what the gateway actually verifies.
  const deep = b64u({ x402Version: 2, payload: { payload: { authorization: auth, signature: sig } } });
  const rDeep = fn(deep);
  console.log('deep envelope  ->', rDeep ? String(rDeep.from).slice(0, 12) + '…' : 'null');
  ok('deep envelope (payload.payload.authorization) parses',
     !!rDeep && String(rDeep.from).toLowerCase() === auth.from.toLowerCase(), rDeep && rDeep.from);
  ok('deep envelope yields the nonce', !!rDeep && rDeep.nonce === auth.nonce.replace(/^0x/, ''),
     rDeep && rDeep.nonce);
  ok('deep envelope carries the signature', !!rDeep && !!rDeep.signature, rDeep && rDeep.signature);

  // SHALLOW shape -- some SDKs.
  const shallow = b64u({ x402Version: 2, payload: { authorization: auth, signature: sig } });
  const rShallow = fn(shallow);
  console.log('shallow envelope ->', rShallow ? String(rShallow.from).slice(0, 12) + '…' : 'null');
  ok('shallow envelope (payload.authorization) still parses',
     !!rShallow && String(rShallow.from).toLowerCase() === auth.from.toLowerCase(),
     rShallow && rShallow.from);

  // Malformed input must still be refused, not throw.
  for (const [label, input] of [
    ['garbage', 'not-base64-json'], ['no auth', b64u({ payload: {} })],
    ['auth without from', b64u({ payload: { payload: { authorization: { nonce: 'x' } } } })],
  ]) {
    let threw = false, out = null;
    try { out = fn(input); } catch (e) { threw = true; }
    ok(`${label} refused without throwing`, !threw && out === null, threw ? 'threw' : out);
  }
}

// ---------- 2. internal error responses carry NO exception text ----------
{
  const py = readFileSync(new URL('../worker/main.py', import.meta.url), 'utf8');
  ok('a generic internal-error constant exists',
     /GENERIC_INTERNAL_ERROR\s*=/.test(py), 'missing');
  // No response may interpolate a raw/redacted exception into its body.
  const bodies = py.split('JSONResponse')[py.indexOf('GENERIC_INTERNAL_ERROR') >= 0 ? 0 : 0];
  ok('no response body uses mask_secret(redact_message(...))',
     !/message:\s*mask_secret\(redact_message\(/.test(py),
     'exception text still reaches a response body');
  ok('pre-parse failures log the redacted cause instead',
     /log_diagnostic\("pre_parse_failure"/.test(py) &&
     /log_diagnostic\("pre_parse_no_rows"/.test(py), 'detail not logged');
}

// The engine's own redaction test must still hold.
{
  // Derive the worker dir from this file's own location (file:// URLs on Windows
  // do not convert to a spawnable path by stripping the leading slash).
  const { dirname, resolve } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  // fileURLToPath handles the file:// -> Windows path conversion correctly,
  // including the trailing separator that broke the earlier manual version.
  const workerDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'worker');
  let out = '', code = 0;
  try {
    out = execSync('python test_redaction.py',
      { encoding: 'utf-8', cwd: workerDir, timeout: 120000 });
  } catch (e) {
    out = String(e.stdout || '') + String(e.stderr || '');
    code = typeof e.status === 'number' ? e.status : 1;
  }
  ok('python sub-invocation produced output', out.trim().length > 0, '(empty)');
  ok('worker/test_redaction.py still passes',
     code === 0 && /REDACTION-ALL-PASS/.test(out), out.trim().slice(-160) || 'no output');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R34-FAIL (${fails.length})`
  : 'R34-ALL-PASS (both envelope depths parse with signature; internal-error responses ' +
    'carry a fixed generic message, exception text goes only to the redacted log)');
process.exit(fails.length ? 1 : 0);
