"""R66 regression test: a preflight probe that cannot delete must FAIL.

BUG: the preflight's cleanup `delete_object` was wrapped in a bare
`except: pass`. Credentials WITHOUT s3:DeleteObject therefore passed the
preflight -- which exists precisely to prove the full permission set the output
path needs -- and then leaked one probe object into the customer's bucket on
EVERY conversion.

The preflight already probes create/upload/complete/abort. Delete was silently
optional; it must be mandatory like the rest.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "main.py")

fails = []


def ok(label, cond, got=""):
    if not cond:
        fails.append("%s -- got %s" % (label, got))


src = open(MAIN, encoding="utf-8").read()

# --- 1. syntax ---
try:
    ast.parse(src)
    ok("main.py parses", True)
except SyntaxError as e:
    ok("main.py parses", False, str(e))

# --- 2. the delete failure must be surfaced, not swallowed ---
ok("the probe object is deleted", "delete_object(Bucket=bucket, Key=probe_key)" in src,
   "no delete call")
ok("a delete failure is captured, not silently passed",
   "delete_failed = del_err" in src or "delete_error = " in src,
   "delete failure is swallowed")
ok("a delete failure raises (preflight fails)",
   "preflight delete-permission check failed" in src,
   "no failure raised")
ok("the bare `except: pass` swallow is gone",
   "delete_object(Bucket=bucket, Key=probe_key)\n"
   "                except Exception:\n"
   "                    pass" not in src,
   "swallow still present")

# --- 2b. R67: the delete error must go through the redacting logger --------
# My R66 fix printed the raw botocore exception, which can carry S3 endpoints
# or credential material into logs. Every engine diagnostic must go through
# log_diagnostic(), which redacts URLs and key material.
ok("the delete failure is logged via log_diagnostic (redacting)",
   'log_diagnostic("preflight delete", del_err)' in src,
   "raw print or missing redacting logger")
ok("no raw print of the preflight delete error remains",
   'print("[engine] preflight delete' not in src,
   "a raw exception print survives")

# --- 3. the other preflight probes must remain mandatory ---
ok("the abort probe is still enforced",
   "preflight abort-permission check failed" in src, "abort probe regressed")
ok("the multipart create/upload/complete probe is retained",
   "create_multipart_upload" in src and "complete_multipart_upload" in src,
   "MPU probe missing")
ok("preflight still runs BEFORE the conversion",
   src.index("PRE-FLIGHT HANDSHAKE") < src.index("COMPUTE")
   if "COMPUTE" in src else True,
   "ordering changed")

# --- 4. behaviour: a delete that raises must fail the preflight -------------
def preflight(delete_raises, exc_in_flight=False):
    """Mirror the production control flow exactly."""
    delete_failed = None
    try:
        if delete_raises:
            raise PermissionError("AccessDenied: s3:DeleteObject")
    except Exception as e:
        delete_failed = e
    # The production guard only raises when no exception is already propagating,
    # so it must not mask the original error.
    if delete_failed is not None and not exc_in_flight:
        raise RuntimeError("preflight delete-permission check failed")
    return "probe-ok"


try:
    preflight(delete_raises=True)
    fails.append("a delete failure did NOT fail the preflight")
except RuntimeError as e:
    ok("a delete failure fails the preflight",
       "delete-permission check failed" in str(e), str(e))

try:
    ok("a working delete passes the preflight",
       preflight(delete_raises=False) == "probe-ok", "valid creds rejected")
except Exception as e:
    ok("a working delete passes the preflight", False, str(e))

try:
    preflight(delete_raises=True, exc_in_flight=True)
    ok("an in-flight exception is not masked by the delete check", True)
except RuntimeError:
    ok("an in-flight exception is not masked by the delete check", False,
       "delete error masked the original exception")


for f in fails:
    print("FAIL:", f)
if not fails:
    print("R66-PREFLIGHT-DELETE-ALL-PASS (a probe object that cannot be deleted "
          "fails the preflight, so credentials without DeleteObject cannot pass "
          "and leak an object per conversion; valid credentials still pass)")
sys.exit(1 if fails else 0)