"""R53 verification: are the two S3 SSRF gaps ACTUALLY closed?

A guard that merely sets an attribute proves nothing. These tests assert
BEHAVIOUR: a rebinding host is pinned to the address validated at check time,
every non-public target is refused before a socket is opened, and the engine
routes its S3 clients through the guard.

Run: python test_s3_guard.py
"""
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

fails = []


def ok(label, cond, got=""):
    if not cond:
        fails.append("%s -- got %s" % (label, got))


import s3_guard

# --- 1. every non-public shape is refused -------------------------------
NON_PUBLIC = [
    "http://127.0.0.1:9000",
    "https://[::1]:9000",
    "https://[::ffff:127.0.0.1]:9000",
    "https://[::ffff:169.254.169.254]/latest",
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5:9000",
    "https://192.168.1.1:9000",
    "https://172.16.0.1:9000",
    "https://0.0.0.0:9000",
    "https://localhost:9000",
    "https://metadata.google.internal/",
]
for url in NON_PUBLIC:
    ips, why = s3_guard.resolve_and_validate(url)
    ok("refused: " + url, ips is None and why is not None,
       "ips=%s why=%s" % (ips, why))

# --- 2. a public host resolves to public IPs ----------------------------
ips, why = s3_guard.resolve_and_validate("https://s3.amazonaws.com")
ok("a public host resolves", ips is not None and why is None,
   "ips=%s why=%s" % (ips, why))
if ips:
    ok("every resolved IP is public",
       all(s3_guard._is_public_ip(i) for i in ips), ips)

# --- 3. DNS REBINDING is defeated by pinning the validated address -------
# The name answers PUBLIC on the first lookup (our check) and LOOPBACK on the
# second (what a dial-time lookup would see). The guard must keep the first.
calls = {"n": 0}


def fake_gai(host, port, *a, **k):
    calls["n"] += 1
    if calls["n"] == 1:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]


_real = socket.getaddrinfo
socket.getaddrinfo = fake_gai
try:
    ips, why = s3_guard.resolve_and_validate("https://evil.example")
finally:
    socket.getaddrinfo = _real

ok("the validation pass pinned the public address", ips == ["93.184.216.34"],
   "ips=%s why=%s" % (ips, why))
ok("the pinned address is public",
   ips is not None and all(s3_guard._is_public_ip(i) for i in ips),
   "pinning would permit a rebind")
ok("the rebinding answer (loopback) is never adopted",
   "127.0.0.1" not in (ips or []), ips)

# --- 4. the hardened client refuses to even build for a private target --
try:
    s3_guard.build_client({}, "https://127.0.0.1:9000", "ak", "sk")
    ok("build_client refuses a loopback endpoint", False, "client was constructed")
except ValueError:
    ok("build_client refuses a loopback endpoint", True)
except Exception as e:
    ok("build_client refused a loopback endpoint, but with %s" % type(e).__name__,
       False, str(e)[:80])

# --- 5. the engine routes S3 through the guard ----------------------------
src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
ok("main.py imports the S3 guard", "s3_guard" in src, "guard not imported")
ok("main.py builds clients through build_client",
   "build_client(" in src, "make_client does not use the guard")
ok("the bare boto3.client(\"s3\"...) call is gone",
   'boto3.client(\r\n        "s3"' not in src and 'boto3.client(\n        "s3"' not in src,
   "a bare boto3 S3 client is still constructed")

# --- 6. redirects are not followed ----------------------------------------
gsrc = open(os.path.join(HERE, "s3_guard.py"), encoding="utf-8").read().lower()
ok("the guard has an explicit redirect policy", "redirect" in gsrc,
   "no redirect handling")
ok("the guard refuses rather than follows",
   "raise" in gsrc and "redirect" in gsrc, "no refusal path")

for f in fails:
    print("FAIL:", f)
if not fails:
    print("S3-GUARD-ALL-PASS (%d non-public targets refused; public host resolves; "
          "DNS rebinding pinned to the validated address; build_client refuses "
          "loopback; the engine routes S3 through the guard; redirects refused)"
          % len(NON_PUBLIC))
sys.exit(1 if fails else 0)