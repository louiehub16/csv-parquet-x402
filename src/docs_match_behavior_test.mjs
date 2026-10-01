// R47 regression test: the public docs must describe what the gateway DOES.
//
// BUG: R46 changed delivery from "return bucket+key" to "stream the bytes", but
// llms.txt, openapi.json, mcp/config and the wrangler comment all still told
// customers they would receive storage coordinates (or a presigned GET). Stale
// docs on a paid API are a real defect: a client written against them cannot
// retrieve what it paid for.
//
// This asserts the docs and the implementation AGREE -- the doc claims are
// compared against the actual src/index.js behaviour, not against themselves.
import { readFileSync } from 'node:fs';

const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

const src = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const llms = readFileSync(new URL('../public/llms.txt', import.meta.url), 'utf8');
const openapi = readFileSync(new URL('../public/openapi.json', import.meta.url), 'utf8');
const mcp = JSON.parse(readFileSync(new URL('../public/mcp/config', import.meta.url), 'utf8'));
const wrangler = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');

// --- ground truth: what does the implementation actually do? --------------
const streams = /new Response\(object\.body/.test(src);
const hasMetaMode = /searchParams\.get\('meta'\) === '1'/.test(src);
ok('ground truth: the gateway STREAMS object.body', streams, 'no streaming response');
ok('ground truth: a ?meta=1 descriptor mode exists', hasMetaMode, 'no meta mode');
ok('ground truth: no presigning is attempted', !/createPresignedUrl/.test(src),
   'presigning reintroduced');

const mcpDesc = mcp.tools[0].description;

// --- 1. no doc may still promise coordinates or a presigned link ----------
for (const [name, text] of [
  ['llms.txt', llms],
  ['openapi.json', openapi],
  ['mcp/config', mcpDesc],
  ['wrangler.jsonc', wrangler],
]) {
  ok(`${name} no longer promises storage coordinates`,
     !/storage coordinates/i.test(text), 'still says "storage coordinates"');
  // A doc may legitimately say a presigned link is NOT returned -- that is the
  // opposite of promising one. Only flag a genuine PROMISE, i.e. a presigned
  // link presented as something the caller receives, with no negation nearby.
  const promise = /(?:returns?|returned|provide[sd]?|issues?|mints?|includes?)[^.|]{0,80}presigned\s+(?:link|url|get)/i;
  for (const m of text.matchAll(/[^.|]{0,120}presigned\s+(?:link|url|get)[^.|]{0,60}/gi)) {
    const sentence = m[0];
    const negated = /\b(not|never|does not|deliberately NOT|no)\b/i.test(sentence);
    if (promise.test(sentence) && !negated) {
      fails.push(`${name} promises a presigned link — got ${JSON.stringify(sentence.trim().slice(0, 110))}`);
    }
  }
  ok(`${name} contains no unqualified presigned-link promise`, true, '');
}

// --- 2. each doc must describe the streaming behaviour ---------------------
ok('llms.txt describes streaming the bytes',
   /streams? the Parquet bytes/i.test(llms), 'no streaming claim');
ok('llms.txt names the PAYMENT-SIGNATURE requirement',
   /PAYMENT-SIGNATURE/.test(llms) && /ref=/.test(llms), 'no auth instructions');
ok('llms.txt mentions the meta descriptor mode', /meta=1/.test(llms), 'no meta=1');
ok('llms.txt keeps the 24h retention note', /24 hours/i.test(llms), 'retention lost');

ok('openapi 200 description describes streaming',
   /STREAMS the Parquet bytes/i.test(openapi), 'no streaming claim');
ok('openapi download_via description describes streaming',
   /streams the Parquet bytes/i.test(openapi), 'no streaming claim on the field');
ok('openapi documents &meta=1', /&meta=1/.test(openapi), 'no meta=1');

ok('mcp/config describes streaming', /streams? the Parquet bytes/i.test(mcpDesc),
   'no streaming claim');
ok('mcp/config keeps the BYO rule for >= 10 GiB',
   /10 GiB/.test(mcpDesc) && /target_destination/.test(mcpDesc), 'BYO rule lost');
ok('mcp/config keeps the 402 payment flow',
   /402/.test(mcpDesc) && /PAYMENT-REQUIRED/.test(mcpDesc), 'payment flow lost');

ok('wrangler comment describes streaming, not presigning',
   /STREAMS the object/i.test(wrangler) && !/mints a SHORT-LIVED presigned/i.test(wrangler),
   'comment still says presigned');

// --- 3. structural integrity after the doc rewrite -----------------------
ok('mcp tool name is unchanged', mcp.tools[0].name === 'compress_csv_stream', mcp.tools[0].name);
ok('mcp protocol_version is unchanged', mcp.protocol_version === '2024-11-05',
   mcp.protocol_version);
ok('mcp inputSchema still requires exactly ["file"]',
   JSON.stringify(mcp.tools[0].inputSchema.required) === '["file"]',
   JSON.stringify(mcp.tools[0].inputSchema.required));
ok('mcp still accepts target_destination',
   'target_destination' in mcp.tools[0].inputSchema.properties,
   Object.keys(mcp.tools[0].inputSchema.properties));
ok('openapi still parses as JSON', (() => { try { JSON.parse(openapi); return true; }
  catch (e) { return false; } })(), 'invalid JSON');
ok('llms.txt has no ragged leftover fragment', !/\)\.\s*The\s*$/m.test(llms),
   'dangling "lifecycle). The"');

// --- 4. the docs must not overstate the security guarantee ---------------
// The gateway verifies the payer against the receipt; it does NOT make the
// object public, and it must not imply anyone can fetch it.
for (const [name, text] of [
  ['llms.txt', llms], ['openapi.json', openapi], ['mcp/config', mcpDesc],
]) {
  ok(`${name} does not imply the object is public`,
     !/public(ly)? (readable|available|accessible)/i.test(text), 'claims public access');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R47-DOCS-FAIL (${fails.length})`
  : 'R47-DOCS-ALL-PASS (llms.txt, openapi.json, mcp/config and wrangler all describe ' +
    'authenticated streaming retrieval; none promise coordinates or a presigned link; ' +
    'mcp/openapi structure and the 10 GiB BYO rule intact)');
process.exit(fails.length ? 1 : 0);
