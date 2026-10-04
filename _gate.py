#!/usr/bin/env python3
"""Canonical gate for csv-parquet-x402.

Two kinds of Python suites live in worker/:
  * real pytest modules (test_*.py that DEFINE test functions)
  * STANDALONE scripts that run assertions at import time and end in
    `sys.exit(1 if fails else 0)` -- running those under pytest raises
    SystemExit at collection time and reports INTERNALERROR, which is a HARNESS
    artifact, not a product failure.

So: probe each file for `def test_` / `unittest` / `pytest` usage; run the
standalone ones with plain `python <file>` and the real modules under pytest.

Node suites are standalone by construction (node <file>).
Exit 1 if ANY suite fails.
"""
import os, re, subprocess, sys, glob, time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "src")
WORKER = os.path.join(ROOT, "worker")

# Helpers/fixtures/signing tools -- not suites.
NOT_SUITES = {"debug_sign.mjs", "mint_vector.mjs", "sign_selftest.mjs"}

EXPLICIT = ["selftest.mjs", "e2e_test.mjs", "gw_smoke.mjs", "integration_test.mjs"]

SHIPPED_JS = ["index.js", "x402.js", "spendguard.js", "budget.js",
             "replay-store.js", "cdp.js", "_secp256k1.js"]


def node_suites():
    out = list(EXPLICIT)
    for p in sorted(glob.glob(os.path.join(SRC, "*_test.mjs"))):
        n = os.path.basename(p)
        if n not in NOT_SUITES and n not in out:
            out.append(n)
    return out


def is_pytest_module(path):
    s = open(path, encoding="utf-8", errors="replace").read()
    if re.search(r"^\s*(def test_|class Test|import unittest|import pytest)", s, re.M):
        return True
    # A module that only calls sys.exit() at import is standalone.
    return False


def run(label, cmd, cwd, timeout):
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return label, 124, time.time() - t0, ["TIMEOUT"], False
    out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return label, r.returncode, time.time() - t0, lines, r.returncode == 0


def main():
    """Gate. Snapshots the fixture vector and restores it on the way out.

    e2e_vector.json is a fixture: mint_vector.mjs mints a throwaway key every
    run, so the file is dirty by design. Restoring the snapshot keeps
    `git status` meaningful -- otherwise every later "is the workspace clean?"
    check is noise. See references/re-verdict-adjudication-probe-discipline.md.
    """
    print("=" * 90)
    print("DISK:", subprocess.run(["df", "-h", "/c"], capture_output=True,
                                  text=True).stdout.strip().splitlines()[-1])
    fails, results = [], []
    vec = os.path.join(SRC, "e2e_vector.json")
    # Restore from git, not from a snapshot: the COMMITTED vector is whatever the
    # last reviewer round graded, so returning to it is both "clean" and the
    # honest state. A snapshot of the pre-run file would only restore whatever
    # stale mint happened to be on disk.
    committed = subprocess.run(["git", "show", "HEAD:src/e2e_vector.json"],
                               cwd=ROOT, capture_output=True)
    try:
        mint = subprocess.run(["node", "mint_vector.mjs"], cwd=SRC,
                              capture_output=True, text=True)
        mline = next((l for l in (mint.stdout or "").splitlines() if "minted" in l), "")
        print("VECTOR:", mline.strip() or ("mint FAILED: " + (mint.stderr or "")[-200:]))
        print("=" * 90)

        print("\n### SYNTAX  (node --check, shipped sources)")
        for f in SHIPPED_JS:
            r = subprocess.run(["node", "--check", "src/" + f], cwd=ROOT,
                               capture_output=True, text=True)
            print(f"  {f:22s} {'OK' if r.returncode == 0 else 'FAIL ' + r.stderr[-200:]}")
            if r.returncode != 0:
                fails.append(f)

        print("\n### NODE SUITES  (standalone, node <file>)")
        for s in node_suites():
            lab, rc, dt, lines, ok = run(s, ["node", s], SRC, 300)
            mark = next((l.strip()[:92] for l in lines
                         if re.search(r"ALL-PASS|ALL PASS|_FAIL|FAILURE|FAIL:|PASS \(", l, re.I)), "")
            print(f"  {s:38s} exit={rc:<3d} {dt:5.1f}s  {mark}")
            results.append((lab, ok))
            if not ok:
                fails.append(s)
                for l in lines[-16:]:
                    print("      " + l[:150])

        print("\n### WORKER PYTHON SUITES")
        for p in sorted(glob.glob(os.path.join(WORKER, "test_*.py"))):
            rel = os.path.relpath(p, ROOT).replace("\\", "/")
            if is_pytest_module(p):
                lab, rc, dt, lines, ok = run(rel, [sys.executable, "-m", "pytest", "-q", rel],
                                             ROOT, 600)
                kind = "pytest"
            else:
                lab, rc, dt, lines, ok = run(rel, [sys.executable, rel], ROOT, 600)
                kind = "script"
            mark = lines[-1][:92] if lines else ""
            print(f"  {rel:38s} [{kind}] exit={rc:<3d} {dt:5.1f}s  {mark}")
            results.append((lab, ok))
            if not ok:
                fails.append(rel)
                for l in lines[-18:]:
                    print("      " + l[:150])

        n = len(results)
        nok = sum(1 for _, ok in results if ok)
        print("\n" + "=" * 90)
        print(f"SUITES: {nok}/{n} green")
        print(("GATE FAIL: " + ", ".join(fails)) if fails else "GATE ALL-GREEN")
        print("=" * 90)
        return 1 if fails else 0


    finally:
        if committed.returncode == 0:
            with open(vec, "wb") as fh:
                fh.write(committed.stdout)


if __name__ == "__main__":
    sys.exit(main())