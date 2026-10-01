"""R18 regression test: credential redaction in the engine.

Reviewer-B round-18 finding: redact_message() masked only URLs and AKIA/ASIA
access-key ids, so an S3 exception carrying the CALLER'S OWN secret access key,
a session token, or a bearer credential leaked verbatim into the HTTP body.

This asserts on BEHAVIOUR (does the secret survive redaction?) rather than on a
substring of the source, so it cannot be satisfied by a docstring that merely
claims the absence.
"""
import importlib.util
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    """Load ONLY the redaction helpers.

    main.py imports pyarrow/boto3 at module scope, which are engine-image
    dependencies absent on a laptop. Importing the whole module would make this
    regression test unrunnable off the engine, so exec just the self-contained
    redaction block (regexes + mask_secret + redact_message + log_diagnostic)
    into a bare namespace.
    """
    import re
    src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
    start = src.index("def mask_secret(")
    end = src.index("DELIMS = (", start)
    ns = {"re": re}
    exec(compile(src[start:end], "main.py:redaction", "exec"), ns)
    return types.SimpleNamespace(**ns)


CASES = [
    # (exception text, secret that must NOT survive, label)
    ("An error occurred (SecretAccessKey) calling PutObject: "
     "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "secret access key (assigned)"),
    ("Access Denied with key AKIAIOSFODNN7EXAMPLE for arn:aws:s3:::b",
     "AKIAIOSFODNN7EXAMPLE", "access key id"),
    ("upstream rejected: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdefgh",
     "eyJhbGciOiJIUzI1NiJ9abcdefgh", "bearer token"),
    ("calling https://s3.example.com/b/k failed with "
     "session_token=FwoGZXIvYXdzEExampleTokenValue123",
     "FwoGZXIvYXdzEExampleTokenValue123", "session token (assigned)"),
    ("auth failed api_key=sk-live-abcdef123456 rejected",
     "sk-live-abcdef123456", "generic api key"),
    ("x_amz_security_token: FwoGZXIvYXdzEAnotherExampleToken9876",
     "FwoGZXIvYXdzEAnotherExampleToken9876", "x-amz security token"),
    # R28: UNLABELED 40-char secret (classic AWS secret-key shape). This is what
    # _BARE_SECRET_RE was written for in R18 but never applied to.
    ("An error occurred (InvalidAccessKeyId): the request signature we calculated "
     "does not match. wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY did not match",
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "unlabeled 40-char secret"),
]


def main():
    mod = _load()
    redact = mod.redact_message

    failures = []
    for text, secret, label in CASES:
        out = redact(text)
        if secret in out:
            failures.append(f"LEAK [{label}]: {out!r}")

    # A URL must still be redacted (pre-existing behaviour must not regress).
    u = redact("failed calling https://s3.example.com/bucket/key")
    if "https://s3.example.com" in u:
        failures.append(f"URL leak: {u!r}")

    # Benign diagnostics must SURVIVE, or the redaction is useless to operators.
    benign = redact("Expected schema drift on column 'amount' (float vs int)")
    if "schema drift" not in benign:
        failures.append(f"over-redacted benign text: {benign!r}")

    # R28: the full response path is mask_secret(redact_message(err)). Verify the
    # COMBINED result leaks no part of a bare secret (mask_secret alone would
    # expose first4...last4).
    combined_src = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    combined = mod.mask_secret(redact(combined_src))
    if "wJalr" in combined or "YKEY" in combined or combined_src in combined:
        failures.append(f"mask_secret(redact()) leaks secret fragments: {combined!r}")

    for f in failures:
        print("FAIL:", f)
    if not failures:
        print(f"REDACTION-ALL-PASS ({len(CASES)} secret shapes masked incl. unlabeled "
              f"40-char, URL masked, benign text preserved, combined path leaks nothing)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
