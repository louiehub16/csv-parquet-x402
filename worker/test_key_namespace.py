"""R52 regression test: BYO output keys must be namespaced per paid job.

BUG: the gateway (R44) rewrites the inbound upload name to
"<16-hex job id>-<original><ext>" so concurrent jobs cannot collide in the
INTERNAL bucket. But the BYO branch of worker/main.py preferred the caller's raw
`file_path` and discarded that prefix, so two customers who both asked for
"data.parquet" wrote to the SAME object in their own bucket -- one silently
overwrote the other, and a payer could be served another tenant's file.

Asserts the key the engine builds, for both BYO and internal paths.
"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_SRC = os.path.dirname(HERE)


def _load():
    """Load ONLY the key-construction helpers.

    Slicing a wide span of main.py drags in engine routes that need pyarrow /
    boto3 / FastAPI symbols, so exec just the one self-contained helper and
    mirror the BYO branch (which is six lines of pure string handling) below.
    """
    src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
    start = src.index("def _job_id_from_filename(")
    end = src.index("def make_client(", start)
    ns = {"str": str, "len": len, "all": all}
    exec(compile(src[start:end], "main.py:keys", "exec"), ns)
    return ns


def build_byo_key(ns, upload_name, file_path):
    """Execute the REAL BYO key branch.

    An earlier version MIRRORED this logic in Python, which made the test pass
    even when the source was reverted -- the negative control silently "passed"
    for the wrong reason. Extract and run the actual branch instead.
    """
    main_src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
    m = main_src.index('            leaf = custom.get("file_path") or file.filename')
    body_start = main_src.index("            parts = []", m)
    body_end = main_src.index("            internal = False", body_start)
    branch = main_src[body_start:body_end]
    # Strip the module-level indentation so the branch can run standalone.
    branch = "\n".join(l[12:] if l.startswith(" " * 12) else l
                       for l in branch.split("\n"))
    env = {"ns": ns, "parts": None, "job_prefix": None}
    # The branch calls _job_id_from_filename and reads file.filename.
    exec("_job_id_from_filename = ns['_job_id_from_filename']", env)
    env["file"] = types.SimpleNamespace(filename=upload_name)
    # `leaf` is the caller's requested path (this is what BYO keys on).
    exec("leaf = %r\n" % (file_path or "upload") + branch, env)
    return env["key"]


def main():
    ns = _load()
    fails = []

    def ok(label, cond, got=""):
        if not cond:
            fails.append(f"{label} — got {got}")

    # --- the helper recovers the gateway's job prefix ---------------------
    extract = ns["_job_id_from_filename"]
    # R57: the gateway emits crypto.randomUUID() with dashes stripped = 32 hex
    # chars. The extractor MUST accept that exact width; a mismatch silently
    # drops the per-job prefix and lets concurrent BYO jobs overwrite each other.
    import re as _re
    gw = open(os.path.join(REPO_SRC, "src", "index.js"), encoding="utf-8").read()
    m = _re.search(r"jobStem\s*=\s*crypto\.randomUUID\(\)\.replace\(([^)]*)\)", gw)
    ok("the gateway emits a randomUUID-derived stem", m is not None, "no randomUUID stem")
    if m:
        dashes_removed = "-" in m.group(1)
        ok("the gateway strips the UUID dashes (so the stem is 32 hex chars)",
           dashes_removed, m.group(1))
        ok("the extractor accepts 32 hex chars",
           extract("ab" * 16 + "-data.csv") == "ab" * 16,
           extract("ab" * 16 + "-data.csv"))
        ok("the extractor still accepts the legacy 16-hex form",
           extract("ab" * 8 + "-data.csv") == "ab" * 8,
           extract("ab" * 8 + "-data.csv"))

    ok("a 16-hex prefix is recovered",
       extract("abababababababab-data.csv") == "abababababababab",
       extract("abababababababab-data.csv"))
    ok("the prefix is case-insensitive",
       extract("ABABABABABABABAB-data.csv") == "abababababababab",
       extract("ABABABABABABABAB-data.csv"))
    for bad, label in [
        ("data.csv", "a plain name yields no prefix"),
        ("short-abc.csv", "a non-16-hex head yields no prefix"),
        ("zzzzzzzzzzzzzzzz-data.csv", "non-hex yields no prefix"),
        ("", "an empty name yields no prefix"),
    ]:
        ok(label, extract(bad) == "", extract(bad))

    # --- two concurrent jobs, same requested path, DIFFERENT keys ---------
    a = build_byo_key(ns, "abababababababab-data.csv", "data.parquet")
    b = build_byo_key(ns, "cdcdcdcdcdcdcdcd-data.csv", "data.parquet")
    print("job A key:", a)
    print("job B key:", b)
    ok("two jobs choosing the same path get DIFFERENT keys", a != b, f"{a} == {b}")
    ok("the caller's requested filename is preserved in both",
       a.endswith("data.parquet") and b.endswith("data.parquet"), f"{a} / {b}")
    ok("the caller's directory prefix is preserved",
       build_byo_key(ns, "abababababababab-data.csv", "reports/q3/data.parquet")
         .endswith("reports/q3/data.parquet"),
       build_byo_key(ns, "abababababababab-data.csv", "reports/q3/data.parquet"))
    ok("traversal is still stripped from a caller path",
       ".." not in build_byo_key(ns, "abababababababab-x.csv", "../../etc/data.parquet"),
       build_byo_key(ns, "abababababababab-x.csv", "../../etc/data.parquet"))

    # --- backwards compatibility: a name with no prefix still works ------
    legacy = build_byo_key(ns, "data.csv", "data.parquet")
    ok("a legacy name (no prefix) still produces a usable key",
       legacy == "data.parquet", legacy)

    # --- the internal path is unchanged (R44 already namespaces it) -------
    src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
    ok("the internal path still uses 'outputs/' + sanitize_key(filename)",
       'key = "outputs/" + sanitize_key(file.filename)' in src,
       "internal key construction changed")
    ok("the BYO branch now namespaces with the job prefix",
       "job_prefix" in src and "_job_id_from_filename(file.filename)" in src,
       "BYO key is not namespaced")

    for f in fails:
        print("FAIL:", f)
    if not fails:
        print("R52-KEY-NAMESPACE-ALL-PASS (BYO keys are prefixed by the paid job id; "
              "two jobs with the same requested path get distinct keys; traversal "
              "stripped; legacy names still work)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
