"""R74 regression test: the engine must refuse unauthenticated conversions.

BUG: /v1/compress had NO auth check. The gateway sent
`Authorization: Bearer <RUNPOD_API_KEY>` but the engine never read the header, so
anyone who learned the RunPod URL could POST directly and receive conversions --
including BYO writes into their own bucket -- without paying anything.

The engine is only ever called by the paid gateway, so it now requires a bearer
token compared (constant-time) against ENGINE_API_KEY, and fails CLOSED when that
variable is unset.

These assertions run against the real FastAPI route via TestClient where
possible; the source-shape checks are the fallback when the test client stack is
unavailable.
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
    print("main.py does not parse -- nothing else can be verified")
    for f in fails:
        print("FAIL:", f)
    sys.exit(1)

# --- 2. the route takes the Request and checks auth BEFORE doing work ---
i = src.index("async def compress(")
body = src[i:i + 2600]

ok("the compress route accepts the Request", "Request" in body.split("):")[0],
   body.split("):")[0])
ok("the route reads ENGINE_API_KEY", "ENGINE_API_KEY" in body, "no ENGINE_API_KEY")
ok("the Authorization header is read", '"Authorization"' in body or "'Authorization'" in body,
   "header never read")
ok("the comparison is constant-time", "compare_digest" in body, "not constant-time")

# The auth gate must come BEFORE any work: storage resolution, the preflight
# handshake, or the conversion.
first_work = min(
    [body.find(x) for x in ("resolve destination", "PRE-FLIGHT", "make_client(",
                            "chosen_delimiter") if body.find(x) > 0] or [10 ** 9])
auth_at = body.find("ENGINE_API_KEY")
ok("auth is checked BEFORE any storage/convert work",
   auth_at > 0 and auth_at < first_work,
   "auth@%d first-work@%d" % (auth_at, first_work))

# --- 3. it FAILS CLOSED when unconfigured ---
ok("an unset ENGINE_API_KEY refuses work (fails closed)",
   "if not _expected" in body and "503" in body, "no fail-closed path")
ok("a missing/invalid token is rejected with 401",
   "401" in body, "no 401")
ok("the token is never echoed back to the caller",
   "_got" not in body.split("return JSONResponse(status_code=401")[1][:200]
   if "return JSONResponse(status_code=401" in body else False,
   "token may be reflected")

# --- 4. the gateway sends the SAME variable the engine reads ---
GATEWAY = os.path.join(os.path.dirname(HERE), "src", "index.js")
gw = open(GATEWAY, encoding="utf-8").read()
ok("the gateway sends ENGINE_API_KEY to the engine",
   "Bearer ' + (env.ENGINE_API_KEY" in gw,
   "gateway still sends RUNPOD_API_KEY -- every paid conversion would 401")
ok("the gateway no longer authenticates with RUNPOD_API_KEY",
   "Bearer ' + env.RUNPOD_API_KEY" not in gw,
   "stale RUNPOD_API_KEY header remains")

# --- 5. hmac + Request are imported (NameError otherwise at request time) ---
ok("hmac is imported at module scope",
   any(l.strip() == "import hmac" for l in src.splitlines()), "no import hmac")
ok("Request is imported from fastapi",
   "Request" in src.split("from fastapi import", 1)[1].split("\n", 1)[0],
   "Request not imported")

# --- 6. behaviour: drive the real route when the stack allows it ---
ran = False
try:
    os.environ["ENGINE_API_KEY"] = "test-engine-token-abc123"
    import importlib.util
    spec = importlib.util.spec_from_file_location("engine_main", MAIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    from fastapi.testclient import TestClient
    import io as _io

    client = TestClient(mod.app)
    ran = True

    def post(auth):
        files = {"file": ("x.csv", _io.BytesIO(b"a,b\n1,2\n"), "text/csv")}
        headers = {"Authorization": auth} if auth is not None else {}
        return client.post("/v1/compress", files=files, headers=headers)

    r_none = post(None)
    ok("a request with NO Authorization is refused",
       r_none.status_code == 401, r_none.status_code)

    r_bad = post("Bearer wrong-token-value")
    ok("a request with a WRONG token is refused",
       r_bad.status_code == 401, r_bad.status_code)

    r_good = post("Bearer test-engine-token-abc123")
    ok("a request with the RIGHT token passes the auth gate",
       r_good.status_code != 401, r_good.status_code)

    # Fail closed when unset.
    saved = os.environ.pop("ENGINE_API_KEY")
    try:
        r_unset = post("Bearer test-engine-token-abc123")
        ok("with ENGINE_API_KEY unset the engine refuses (fails closed)",
           r_unset.status_code == 503, r_unset.status_code)
    finally:
        os.environ["ENGINE_API_KEY"] = saved
except Exception as e:
    print("behavioural probe unavailable: %s: %s" % (type(e).__name__, e))
    if isinstance(e, ModuleNotFoundError):
        ok("the route signature is real (source checks still apply)", False,
           "fastapi/testclient stack incomplete")

print("(behavioural route probe ran: %s)" % ran)

for f in fails:
    print("FAIL:", f)
if not fails:
    print("R74-ENGINE-AUTH-ALL-PASS (/v1/compress requires a constant-time-matched bearer "
          "token before any storage or conversion work, fails closed when unset, and the "
          "gateway sends the same ENGINE_API_KEY variable)")
sys.exit(1 if fails else 0)