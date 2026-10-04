#!/usr/bin/env python3
"""Negative control for the R82 fixture fix.

The fix made the settlement-receipt fixtures derive the payer topic from
`vec.payer_expected` instead of a hardcoded address. These mutations each
re-introduce a real defect and MUST turn the suite red:

  N1: receipt topics carry a payer that is NOT the vector's payer
      -> the on-chain proof cannot bind -> must be 502, suite must FAIL.
  N2: drop the AuthorizationUsed log (keep only the Transfer)
      -> a bare Transfer must not unlock paid work -> must be 502, suite FAILs.
  N3: emit a Transfer for MORE than the authorized value
      -> R63 requires exact equality -> must FAIL.

Run each in a throwaway copy of src/.
"""
import os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
VEC = os.path.join(SRC, "e2e_vector.json")

TARGETS = ["integration_test.mjs", "timeout_durability_test.mjs"]


def fresh_vector():
    """Copy the CURRENT vector so every mutation run sees the same payer."""
    import json
    return json.load(open(VEC, encoding="utf-8"))


def mutate_wrong_payer(s):
    return s.replace("const payerTopic = '0x' + String(vec.payer_expected).toLowerCase().replace(/^0x/, '');",
                     "const payerTopic = '0x' + '11'.repeat(20);  // R82-CONTROL wrong payer")


def mutate_drop_authused(s):
    """Remove ONLY the AuthorizationUsed log object from integration_test's receipt.

    The first attempt spliced from the '{ address:' token to the next ']', which
    ran through the comment block above the object and produced a parse error --
    an INCONCLUSIVE control. This version locates the object by brace balance
    starting at its own '{', so comments cannot be caught.
    """
    TOPIC = "'0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5'"
    i = s.find(TOPIC)
    if i < 0:
        return s
    # the object literal opens with '{' and the preceding '[' / ',' separators
    start = s.rfind("{", 0, i)
    # confirm nothing but this object lies between start and the topic
    depth = 0
    close = None
    for k in range(start, len(s)):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                close = k
                break
    if close is None:
        return s
    # swallow the trailing comma/bracket so the array stays well-formed
    end = close + 1
    while end < len(s) and s[end] in ", \r\n":
        end += 1
    return s[:start] + s[end:]


def mutate_overpay(s):
    return s.replace("data: '0x' + (10000).toString(16).padStart(64, '0') }",
                     "data: '0x' + (20000).toString(16).padStart(64, '0') }")


def run(name, mutate, target):
    sb = tempfile.mkdtemp(prefix="r82-fx-")
    try:
        d = os.path.join(sb, "src")
        shutil.copytree(SRC, d)
        p = os.path.join(d, target)
        s = open(p, encoding="utf-8", newline="").read()
        new = mutate(s)
        if new == s:
            print(f"  {name} [{target}]: mutation did NOT apply -- INCONCLUSIVE")
            return None
        open(p, "w", encoding="utf-8", newline="").write(new)
        chk = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        if chk.returncode != 0:
            print(f"  {name} [{target}]: does not parse -- INCONCLUSIVE")
            return None
        r = subprocess.run(["node", target], cwd=d, capture_output=True,
                           text=True, timeout=200)
        fails = [l.strip() for l in (r.stdout or "").splitlines()
                 if "FAIL" in l or "FAIL(" in l]
        print(f"  {name} [{target}]: exit={r.returncode} "
              f"{'RED (detects)' if r.returncode else 'GREEN <-- PROBLEM'}")
        for l in fails[:3]:
            print("     ", l[:118])
        return r.returncode
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def main():
    v = fresh_vector()
    print("vector payer:", v["payer_expected"])
    print("NEGATIVE CONTROL for the R82 receipt-fixture fix")
    print("-" * 78)
    results = {}
    for t in TARGETS:
        results[("N1", t)] = run("N1 receipt payer != vector payer", mutate_wrong_payer, t)
    results[("N2", "integration_test.mjs")] = run(
        "N2 AuthorizationUsed log dropped (bare Transfer only)", mutate_drop_authused,
        "integration_test.mjs")
    results[("N3", "integration_test.mjs")] = run(
        "N3 Transfer amount != authorized (20000 vs 10000)", mutate_overpay,
        "integration_test.mjs")
    print("=" * 78)
    # every mutation must be RED, and the vector's real payer must NOT appear
    ok = all(r not in (None, 0) for r in results.values())
    print("VERDICT:", "CONTROL VALID -- the suites reject an unbound/overpaying receipt"
          if ok else "CONTROL INVALID -- a mutation went undetected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())