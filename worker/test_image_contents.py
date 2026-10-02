"""R61 regression test: the engine image must ship every module main.py imports.

BUG: `COPY main.py .` shipped only the entrypoint. main.py imports s3_guard
inside make_client, so every conversion would fail during preflight with
ModuleNotFoundError -- the service would accept payments and deliver nothing.

This compares the Dockerfile's COPY list against the modules main.py actually
imports, so adding an import without adding the file fails here instead of at
runtime in production.
"""
import ast
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Modules that are either in the image's pip install list or the Python
# standard library -- NOT files that must be COPY'd into the image.
THIRD_PARTY_AND_STDLIB = {
    # pip-installed in the Dockerfile
    "boto3", "botocore", "pyarrow", "fastapi", "uvicorn", "numpy", "pandas",
    "multipart",
    # stdlib
    "abc", "argparse", "ast", "asyncio", "base64", "collections", "contextlib",
    "copy", "csv", "datetime", "decimal", "functools", "gc", "glob", "hashlib",
    "hmac", "io", "ipaddress", "itertools", "json", "logging", "math", "mimetypes",
    "os", "pathlib", "queue", "random", "re", "secrets", "shutil", "socket",
    "sqlite3", "ssl", "string", "sys", "tempfile", "textwrap", "threading",
    "time", "traceback", "types", "typing", "unicodedata", "urllib", "uuid",
    "warnings", "zipfile",
}
sys.path.insert(0, HERE)

fails = []


def ok(label, cond, got=""):
    if not cond:
        fails.append("%s -- got %s" % (label, got))


# --- 1. the local modules main.py imports ---------------------------------
main_src = open(os.path.join(HERE, "main.py"), encoding="utf-8").read()
tree = ast.parse(main_src)

local_modules = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for a in node.names:
            if a.name.split(".")[0] not in THIRD_PARTY_AND_STDLIB:
                local_modules.add(a.name.split(".")[0])
    elif isinstance(node, ast.ImportFrom):
        if node.level and node.level > 0 and node.module:      # relative import
            local_modules.add(node.module.split(".")[0])
        elif node.module and node.module.split(".")[0] not in THIRD_PARTY_AND_STDLIB:
            local_modules.add(node.module.split(".")[0])

# function-level imports are not in the module tree, so scan the source too
for m in re.finditer(r"^\s*import\s+([A-Za-z_][\w]*)", main_src, re.M):
    name = m.group(1)
    if name not in THIRD_PARTY_AND_STDLIB:
        local_modules.add(name)

print("local modules main.py imports:", sorted(local_modules))
ok("s3_guard is imported by main.py", "s3_guard" in local_modules,
   sorted(local_modules))

# --- 2. the Dockerfile must ship every one of them ------------------------
docker = open(os.path.join(HERE, "Dockerfile"), encoding="utf-8").read()
copied = set()
for line in docker.splitlines():
    m = re.match(r"\s*COPY\s+(.*)", line)
    if not m:
        continue
    for tok in m.group(1).split():
        if tok in (".", "./", "-", "/app"):
            continue
        if tok.endswith(".py"):
            copied.add(tok)
print("Dockerfile COPYs:", sorted(copied))

ok("main.py is copied into the image", "main.py" in copied, sorted(copied))
missing = sorted(m + '.py' for m in (local_modules - {c[:-3] for c in copied}))
ok("every locally-imported module is in the image", not missing,
   "missing from COPY: %s" % missing)

# --- 3. the guard module itself must exist on disk -------------------------
for mod in local_modules:
    ok("worker/%s.py exists" % mod, os.path.exists(os.path.join(HERE, mod + ".py")),
       "missing file")

# --- 4. guard against re-introducing the bug ------------------------------
ok("the Dockerfile no longer copies main.py ALONE",
   not re.search(r"^\s*COPY\s+main\.py\s+\.\s*$", docker, re.M),
   "single-module COPY present")

for f in fails:
    print("FAIL:", f)
if not fails:
    print("DOCKER-IMAGE-ALL-PASS (%d local modules imported, all %d copied into "
          "the image; a single-module COPY would be caught)"
          % (len(local_modules), len(copied)))
sys.exit(1 if fails else 0)