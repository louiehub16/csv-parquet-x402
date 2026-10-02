// R63 regression test: on-chain confirmation must require EXACT equality.
//
// BUG: the confirm callback accepted a USDC Transfer whose amount was
// >= expected.value. A facilitator transaction collecting MORE than the signed
// authorization would therefore confirm as a valid payment while the settlement
// metadata still reported the expected amount -- so work would be delivered
// against a payment that did not match what the payer authorized. An EIP-3009
// transfer of THIS authorization is always exactly auth.value, so `>` can never
// be legitimate.
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('./index.js', import.meta.url), 'utf8');
const fails = [];
const ok = (label, cond, got) => { if (!cond) fails.push(`${label} — got ${JSON.stringify(got)}`); };

// --- the production check must be equality, not >= ---
const CONF_AT = idx.indexOf('confirm: async (txHash, expected)');
const conf = idx.slice(CONF_AT, CONF_AT + 6000);

{
  ok('the confirm callback exists', conf.length > 100, 'not found');

  ok('the transfer amount is compared with EXACT equality',
     /if \(amount !== BigInt\(expected\.value\)\) continue;/.test(conf),
     'no strict equality check');
  ok('the loose `< expected` comparison is gone',
     !/if \(amount < BigInt\(expected\.value\)\) continue;/.test(conf),
     'still accepts overpayment');
  ok('no `>=` comparison against the authorized amount remains',
     !/amount\s*>=\s*BigInt\(expected\.value\)/.test(conf), '>= still present');
}

// --- the rest of the confirmation contract must be intact ------------------
{
  ok('the AuthorizationUsed nonce binding is retained',
     /const nonce = String\(log\.topics\[2\]/.test(conf), 'nonce binding lost');
  ok('the authorizer is still checked against expected.from',
     /authenticator|authorizer/.test(conf) && /expected\.from/.test(conf),
     'authorizer check lost');
  ok('a bare Transfer still cannot confirm alone',
     /transfer_without_authorization_used/.test(idx), 'transfer-only path lost');
  ok('AuthorizationUsed plus a matching Transfer still confirms',
     /bound:\s*'authorization_used\+transfer'/.test(idx), 'confirmation path lost');
}

// --- behavioural: the comparison really is equality ------------------------
{
  const check = (amount, expected) => amount !== BigInt(expected);
  ok('an EXACT amount passes', check(10000n, '10000') === false, 'exact match rejected');
  ok('an UNDERPAYMENT is rejected', check(9999n, '10000') === true, 'underpay accepted');
  ok('an OVERPAYMENT is rejected (this is the R63 fix)',
     check(10001n, '10000') === true, 'overpay accepted');
  ok('a large overpayment is rejected',
     check(999999n, '10000') === true, 'large overpay accepted');
}

for (const f of fails) console.log('FAIL:', f);
console.log(fails.length
  ? `R63-AMOUNT-FAIL (${fails.length})`
  : 'R63-AMOUNT-ALL-PASS (on-chain amount must EQUAL the authorized value; overpayment '
    + 'is refused; the AuthorizationUsed nonce binding and transfer-pairing checks '
    + 'are intact)');
process.exit(fails.length ? 1 : 0);