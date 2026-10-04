#!/usr/bin/env python3
"""Negative control for budget_order_test.mjs (R82).

Two mutations, each in a THROWAWAY copy of src/:
  M1: move reserveDailyBudget OUT of settle() and back BEFORE verifyPayment()
      (re-introduce the R80 bug). The suite MUST go red.
  M2: keep the reservation inside settle() but put it AFTER the facilitator
      call. The suite MUST go red.
Plus a robustness check:
  M3: insert ~30 lines of filler INSIDE the settle callback (simulating a
      larger future edit). The suite MUST stay GREEN -- this is the exact
      failure the hardcoded 2600-char window caused, so it must not recur.
"""
import os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
RESERVE = "reserveDailyBudget(env, est, budgetTxId)"
VERIFY = "v = await verifyPayment(env, request, {"
FACIL = "cdpVerifyAndSettle"


def run_in_copy(name, mutate):
    sb = tempfile.mkdtemp(prefix="r82-ctl-")
    try:
        d = os.path.join(sb, "src")
        shutil.copytree(SRC, d)
        p = os.path.join(d, "index.js")
        src = open(p, encoding="utf-8").read()
        new = mutate(src)
        if new == src:
            print(f"  {name}: MUTATION DID NOT APPLY (anchor miss) -- INCONCLUSIVE")
            return None
        open(p, "w", encoding="utf-8", newline="").write(new)
        chk = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        if chk.returncode != 0:
            print(f"  {name}: mutated file does not parse -- INCONCLUSIVE")
            print("   ", chk.stderr[-300:])
            return None
        r = subprocess.run(["node", "budget_order_test.mjs"], cwd=d,
                           capture_output=True, text=True, timeout=200)
        fails = [l.strip() for l in (r.stdout or "").splitlines() if "FAIL" in l]
        print(f"  {name}: exit={r.returncode} {'RED (detects)' if r.returncode else 'GREEN'}")
        for l in fails[:4]:
            print("     ", l[:120])
        return r.returncode
    finally:
        shutil.rmtree(sb, ignore_errors=True)


def m1_revert_before_verify(src):
    """Pull the reservation line out of settle() and re-insert it before verifyPayment."""
    line = "            const res = await " + RESERVE + ";"
    assert src.count(line) == 1, f"reserve line count={src.count(line)}"
    body = src.replace(line, "", 1)
    m = re.search(r"^([ \t]*)v = await verifyPayment\(", body, re.M)
    assert m, "verifyPayment anchor missing"
    ind = m.group(1)
    injected = (ind + "// R82-CONTROL: pre-verification reservation (the R80 bug)\n"
                + ind + "await " + RESERVE + ";\n\n")
    return body[:m.start()] + injected + body[m.start():]


def m2_reserve_after_facilitator(src):
    """Keep the reservation in settle(), but place it AFTER the facilitator call.

    CORRECTED after the first control run: the original version inserted the
    line immediately BEFORE `await cdpVerifyAndSettle`, which is the SAFE
    ordering -- so it proved nothing about ordering. This version re-inserts it
    just before the settle callback's closing brace, i.e. after the facilitator
    has already been contacted, which is the real defect.
    """
    line = "          const res = await " + RESERVE + ";"
    assert src.count("            const res = await " + RESERVE + ";") == 1
    body = src.replace("            const res = await " + RESERVE + ";\n", "", 1)
    f = body.index("settle: async")
    # brace-match the settle callback, then inject before its closing brace
    open_i = body.index("{", f)
    depth = 0
    close_i = None
    for i in range(open_i, len(body)):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                close_i = i
                break
    assert close_i, "could not find the end of the settle callback"
    return body[:close_i] + "          // R82-CONTROL: reserved only after the facilitator\n" + \
        line + "\n" + body[close_i:]


def m3_bulk_insert(src):
    """Add 30 lines INSIDE the settle callback: must stay GREEN."""
    f = src.index("await " + FACIL)
    filler = "".join(f"            // R82-CONTROL filler line {i}\n" for i in range(30))
    return src[:f] + filler + src[f:]


def main():
    print("NEGATIVE CONTROL for budget_order_test.mjs")
    print("-" * 70)
    r1 = run_in_copy("M1 reservation moved BEFORE verifyPayment (the R80 bug)", m1_revert_before_verify)
    print("-" * 70)
    r2 = run_in_copy("M2 reservation moved AFTER the facilitator call", m2_reserve_after_facilitator)
    print("-" * 70)
    r3 = run_in_copy("M3 +30 filler lines inside settle() (robustness)", m3_bulk_insert)
    print("=" * 70)
    ok = (r1 not in (None, 0)) and (r2 not in (None, 0)) and (r3 == 0)
    print("VERDICT:", "CONTROL VALID -- the suite detects both real defects and"
          " survives unrelated insertions" if ok else "CONTROL INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())