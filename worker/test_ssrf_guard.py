"""R26 regression test: SSRF guard for a caller-supplied S3 endpoint.

BUG: the engine validated only that target_destination was a well-shaped JSON
object; it never checked the endpoint host. boto3 would then dial whatever the
caller asked for -- including loopback, link-local cloud metadata, and
IPv4-mapped IPv6 forms like [::ffff:127.0.0.1] that slip past a dotted-quad
regex.

Asserts BEHAVIOUR of validate_endpoint_url() on real inputs.
"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    """Load only the URL/SSRF helpers (main.py imports pyarrow/boto3, absent here)."""
    src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
    start = src.index("# R26: SSRF guard")
    end = src.index("DELIMS = (", start)
    ns = {}
    exec(compile(src[start:end], "main.py:ssrf", "exec"), ns)
    return types.SimpleNamespace(**ns)


# (url, must_be_rejected, label)
CASES = [
    # --- non-public literals, including IPv4-mapped IPv6 ---
    ("https://127.0.0.1:9000", True, "loopback v4"),
    ("https://[::1]:9000", True, "loopback v6"),
    ("https://[::ffff:127.0.0.1]:9000", True, "IPv4-mapped loopback (the reported bypass)"),
    ("https://[::ffff:10.0.0.1]:9000", True, "IPv4-mapped private"),
    ("https://[::ffff:169.254.169.254]:9000", True, "IPv4-mapped cloud metadata"),
    ("https://169.254.169.254/latest", True, "cloud metadata direct"),
    ("https://10.0.0.5:9000", True, "private 10/8"),
    ("https://192.168.1.10:9000", True, "private 192.168/16"),
    ("https://172.16.5.5:9000", True, "private 172.16/12"),
    ("https://0.0.0.0:9000", True, "unspecified"),
    # --- alternate encodings a parser may normalise ---
    ("https://2130706433:9000", True, "decimal loopback"),
    ("https://0x7f000001:9000", True, "hex loopback"),
    ("https://[0:0:0:0:0:ffff:127.0.0.1]:9000", True, "expanded IPv4-mapped loopback"),
    # --- non-public names ---
    ("https://localhost:9000", True, "localhost"),
    ("https://bucket.internal:9000", True, ".internal"),
    ("https://printer.local:9000", True, ".local"),
    # --- scheme ---
    ("http://s3.example.com", True, "plaintext http"),
    ("ftp://s3.example.com", True, "non-https scheme"),
    # --- genuinely public endpoints must be ALLOWED ---
    ("https://s3.amazonaws.com", False, "public S3"),
    ("https://accountid.r2.cloudflarestorage.com", False, "public R2"),
    ("https://minio.example.com:9000", False, "public minio"),
]


def main():
    mod = _load()
    validate = mod.validate_endpoint_url

    failures = []
    for url, should_reject, label in CASES:
        try:
            why = validate(url)
        except Exception as e:  # a guard that raises is not a guard
            failures.append(f"{label}: validate() raised {type(e).__name__}: {e}")
            continue
        rejected = bool(why)
        if rejected != should_reject:
            verdict = "REJECTED" if rejected else "ALLOWED"
            want = "REJECTED" if should_reject else "ALLOWED"
            failures.append(f"{label} ({url}): {verdict} but must be {want}"
                            + (f" [reason: {why}]" if why else ""))

    for f in failures:
        print("FAIL:", f)
    if not failures:
        print(f"SSRF-GUARD-ALL-PASS ({len(CASES)} cases: "
              f"{sum(1 for c in CASES if c[1])} rejected incl. IPv4-mapped IPv6, "
              f"{sum(1 for c in CASES if not c[1])} public endpoints allowed)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
