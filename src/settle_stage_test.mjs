// R54/R55 regression tests.
//
//  1. R54 -- an UNPAID authorization must never trigger a refund. The CDP
//     adapter had no notion of which stage it was in, so a failure at /verify
//     (or before /settle was even submitted) returned an ambiguous outcome and
//     the gateway could schedule a REFUND for money that was never collected.
//
//  2. R55 -- the per-job key stem must not be derived from a payer-controlled
//     64-bit nonce prefix. Two authorizations sharing that prefix would collide
//     and one paid job would overwrite the other.
import { readFileSync } from 'node:fs';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// ---------- 1. every pre-submit failure is definitelyNotSubmitted ----------
{
  const cdp = readFileSync(new URL('./cdp.js', import.meta.url), 'utf8');

  // The /verify 2xx path: isValid !== true.
  const v = cdp.slice(cdp.indexOf('if (!vData || vData.isValid !== true)'),
                      cdp.indexOf('if (!vData || vData.isValid !== true)') + 1400);
  ok('the verify 2xx path declares stage "verify"',
     /stage:\s*'verify'/.test(v), 'no stage marker');
  ok('the verify 2xx path is unconditionally definitelyNotSubmitted',
     /definitelyNotSubmitted:\s*true/.test(v) &&
     !/definitelyNotSubmitted:\s*isRej/.test(v),
     'still conditional on wording');
  ok('the verify 2xx path no longer returns settledUnknown',
     !/settledUnknown/.test(v), 'still marked ambiguous');

  // The /verify HTTP path.
  const h = cdp.slice(cdp.indexOf('const perm = isPermanentRejection('),
                      cdp.indexOf('const perm = isPermanentRejection(') + 1100);
  ok('the verify HTTP path is unconditionally definitelyNotSubmitted',
     /definitelyNotSubmitted:\s*true/.test(h) &&
     !/definitelyNotSubmitted:\s*perm === true/.test(h),
     'still conditional on isPermanentRejection');

  // The settle-preflight (JWT) path.
  // Read the preflight branch LINE BY LINE: the previous start/end anchors did
  // not match the same occurrence, so slice() collapsed to an empty string.
  const jl = cdp.split('\n');
  const jStart = jl.findIndex((l) => l.includes('const jwtS = await buildCdpJwt('));
  const j = jl.slice(jStart, jStart + 10).join('\n');
  ok('the settle preflight block was located', jStart >= 0, 'anchor not found');
  ok('a settle JWT failure is definitelyNotSubmitted (nothing submitted)',
     /stage:\s*'settle-preflight'/.test(j) && /definitelyNotSubmitted:\s*true/.test(j),
     j.slice(0, 220));

  // settledUnknown must now only appear AFTER a settle request was submitted.
  const unknownSites = [...cdp.matchAll(/settledUnknown:\s*true/g)].map((m) => m.index);
  const settleCall = cdp.indexOf('`${CDP_BASE}/settle`');
  // R65: stage tracking. The catch-all must distinguish a failure BEFORE the
  // settle request was submitted (nothing moved -> no refund) from one after
  // (genuinely ambiguous -> refund path).
  ok('the adapter tracks the current stage',
     /let stage = 'verify'/.test(cdp), 'no stage variable');
  ok('it tracks whether the settle request was submitted',
     /let settleSubmitted = false/.test(cdp), 'no submit flag');
  ok('the flag is set immediately before the settle fetch',
     cdp.indexOf('settleSubmitted = true;') < cdp.indexOf('`${CDP_BASE}/settle`'),
     'flag set after the request');
  ok('a PRE-submit exception is definitelyNotSubmitted (no fabricated refund)',
     /if \(!settleSubmitted\)[\s\S]{0,400}definitelyNotSubmitted:\s*true/.test(cdp),
     'pre-submit failure still reported ambiguous');
  ok('a POST-submit exception stays settledUnknown',
     /settleSubmitted = true[\s\S]*?settledUnknown:\s*true/.test(cdp),
     'post-submit failure no longer ambiguous');

  ok('settledUnknown only appears after the settle request is built',
     unknownSites.length > 0 && unknownSites.every((i) => i > settleCall),
     `${unknownSites.length} sites, first at ${unknownSites[0]}, settle at ${settleCall}`);
}

// ---------- 2. the job stem is gateway-generated, not a payer nonce ----------
{
  const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
  const stemLine = (idx.split('\n').find((l) => l.includes('const jobStem =')) || '');
  const s = stemLine;
  ok('the stem is a gateway-generated UUID',
     /crypto\.randomUUID\(\)/.test(s), 'not a random UUID');
  ok('the stem is NOT truncated to 16 hex chars (64 bits)',
     !/slice\(0,\s*16\)/.test(s), 'stem is still truncated');
  ok('the stem does not derive from the payer-controlled nonce',
     !/v\.nonce/.test(s), 'still derived from the nonce');
  ok('the full 128-bit id is used (32 hex chars, no slice)',
     /replace\(\/-\/g,\s*''\)/.test(s) && !/slice\(/.test(s), 'stem is sliced');

  // A full-length stem must not make the upload name exceed sane key limits.
  const upload = idx.slice(idx.indexOf('const uploadName ='),
                           idx.indexOf('const uploadName =') + 200);
  ok('the upload name is still <jobStem>-<stem><ext>',
     /\$\{jobStem\}-\$\{baseStem\}\$\{ext\}/.test(upload), 'name shape changed');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R54-R55-FAIL (${fails.length})`
  : 'R54-R55-ALL-PASS (verify-stage and settle-preflight failures are '
    + 'definitelyNotSubmitted, so an unpaid authorization cannot trigger a refund; '
    + 'settledUnknown only after a submitted settle; the job stem is a full '
    + 'gateway-generated 128-bit id, not a payer-controlled 64-bit nonce prefix)');
process.exit(fails.length ? 1 : 0);