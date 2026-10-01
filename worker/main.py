"""x402 Parquet Engine — RunPod serverless CPU container (FastAPI + uvicorn).

Rewrite of the vendor spec engine with the review-driven fixes applied:
- pre-flight storage handshake BEFORE compute (bad creds die in milliseconds,
  not after minutes of parsing)
- S3 multipart writer that ALWAYS aborts orphan uploads (orphan parts bill)
- Mid-file TYPE drift triggers one automatic all-string re-read (lossless,
  drift_fallback=true). Column-COUNT drift rows are SKIPPED and counted via
  invalid_row_handler (skipped_rows); the stream completes 200. The gateway
  sniffs binary/NUL before paid dispatch.
- API responses carry FIXED generic messages only ('Conversion failed.' /
  verbatim preflight text); raw exception text never leaves the process.
  Diagnostics go to stdout only, with URLs and AKIA-style keys redacted.
- NO use_byte_stream_split on the parquet writer (invalid for string columns)
"""
import io
import json
import gc
import os
import re
import time

import boto3
from botocore.config import Config
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pv
import pyarrow.parquet as pq
from fastapi import FastAPI, Form, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(title="x402-parquet-engine")

PART_SIZE = 15 * 1024 * 1024          # S3 min part size except last part
GC_EVERY = 50                          # chunks between gc.collect() sweeps
CPU_RATE_PER_HR = float(os.getenv("CPU_RATE_PER_HR", "0.13"))
ALLOWED_INPUT_EXT = (".csv", ".tsv", ".txt")


def mask_secret(s: str) -> str:
    """Never log a full credential."""
    s = str(s or "")
    if len(s) < 12:
        return "***"
    return s[:4] + "..." + s[-4:]


_URL_RE = re.compile(r"https?://\S+")
_AKIA_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# R18: S3/botocore exception text embeds the CALLER's own secret access key and
# session token, and an upstream endpoint may hand back a bearer credential.
# Masking only URLs + AKIA/ASIA leaked those verbatim into the response body.
# Order matters: longest/most specific pattern first, generic last.
_CRED_ASSIGN_RE = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_access_key_id|secret_access_key|"
    r"session_token|x_amz_security_token|bearer|authorization|api[_-]?key|"
    r"secret|token|password|passwd|credential)\b\s*[:=]\s*[\"']?([^\s,\"';]{4,})")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}")
# A bare 40-char secret (classic AWS secret key shape) with no label nearby.
_BARE_SECRET_RE = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")


# R34: The response for an internal failure must never carry exception text.
# mask_secret() keeps the first and last four characters of anything >= 12 chars,
# and redaction only strips UNLABELED 40-char secrets -- so a shorter credential
# (access key id, token, password) passed through and 8 of its characters were
# published in the HTTP body. Client-facing text is now a fixed generic string.
GENERIC_INTERNAL_ERROR = "Internal conversion error."


def redact_message(err) -> str:
    """Redact endpoint URLs, access-key ids, and generic credential material
    from an exception/message so the result is safe to embed in a (masked) HTTP
    response body while keeping the user-facing diagnostic text intact. Raw
    credentials never leave the process."""
    msg = _URL_RE.sub("<redacted-url>", str(err or ""))
    msg = _AKIA_RE.sub("<redacted-key>", msg)
    msg = _BEARER_RE.sub("Bearer <redacted>", msg)
    # Keep the label (it is diagnostic) but never the value.
    msg = _CRED_ASSIGN_RE.sub(lambda m: f"{m.group(1)}=<redacted>", msg)
    # R28: apply the bare-secret rule. It was defined in R18 but never wired in,
    # so an UNLABELED 40-character secret (classic AWS secret-key shape) passed
    # through untouched and mask_secret() then exposed its first and last 4
    # characters in the response body.
    msg = _BARE_SECRET_RE.sub("<redacted-secret>", msg)
    return msg


def log_diagnostic(where: str, err) -> None:
    """Internal stdout diagnostics ONLY — never an HTTP response body.
    Redacts endpoint URLs and AKIA-style keys, then masks the remainder."""
    try:
        print(f"[engine] {where}: {mask_secret(redact_message(err))}", flush=True)
    except Exception:
        pass


# R26: SSRF guard for a caller-supplied S3 endpoint. The gateway filters the
# URL syntactically, but THIS process is the one that actually opens the socket,
# so it must validate the host AND the addresses it resolves to. Crucially this
# covers IPv4-mapped IPv6 forms such as [::ffff:127.0.0.1], which bypass a
# dotted-quad-only check and otherwise reach loopback/private infrastructure.
import ipaddress
import socket
from urllib.parse import urlparse


def _forbidden_host(host: str) -> str:
    """Return a reason string if the host is unsafe to dial, else ''."""
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return "empty host"
    if h in ("localhost",) or h.endswith((".internal", ".local", ".localhost")):
        return "private hostname"
    # Alternate integer encodings a dialer normalises into an IPv4 address:
    # '2130706433' == 127.0.0.1, '0x7f000001' == 127.0.0.1. ipaddress cannot
    # parse these, so they are rejected before any resolution is attempted.
    if h.isdigit() or (h.startswith("0x") and all(c in "0123456789abcdefABCDEF"
                                                  for c in h[2:]) and len(h) > 2):
        return "non-decimal-safe integer host"
    if h == "metadata.google.internal" or h.startswith("169.254."):
        return "cloud metadata"
    # Any IP literal (v4, v6, or v4-mapped v6) is checked in its NUMERIC form.
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return ""            # not a literal -> resolved below
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved \
            or ip.is_multicast or ip.is_unspecified:
        return "non-public IP"
    # ::ffff:127.0.0.1 and friends collapse to the embedded IPv4 address.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and (mapped.is_loopback or mapped.is_private
                               or mapped.is_link_local):
        return "IPv4-mapped non-public IP"
    return ""


def _resolve_all_public(host: str):
    """Resolve host and ensure EVERY address is publicly routable (anti-rebind).

    A resolution FAILURE is NOT treated as a rejection: a transient DNS failure
    must not lock a customer out of their own bucket (and the request will fail
    naturally on connect if the host is truly dead). Only a successful
    resolution that PROVES a non-public target is refused."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return ""              # cannot prove anything -> allow, let connect fail
    if not infos:
        return ""
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return "unparsable resolved address"
        if ip.is_loopback or ip.is_private or ip.is_link_local or \
                ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return "host resolves to a non-public address"
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None and (mapped.is_loopback or mapped.is_private
                                   or mapped.is_link_local):
            return "host resolves to an IPv4-mapped non-public address"
    return ""


def validate_endpoint_url(url: str) -> str:
    """Return '' if the endpoint is an acceptable public HTTPS S3 endpoint."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "unparsable endpoint_url"
    if parsed.scheme != "https":
        return "endpoint_url must be https"
    if not parsed.hostname:
        return "endpoint_url has no host"
    why = _forbidden_host(parsed.hostname)
    if why:
        return why
    return _resolve_all_public(parsed.hostname)


DELIMS = (",", ";", "\t")


def choose_delimiter(filename: str, fobj) -> str:
    """Derive the input delimiter from the filename extension:
    .tsv -> tab, .csv -> comma, .txt -> sniff the first 64KB and take the
    most frequent candidate of comma/semicolon/tab (ties break to comma)."""
    low = str(filename or "").lower()
    if low.endswith(".tsv"):
        return "\t"
    if low.endswith(".csv"):
        return ","
    sample = fobj.read(65536)
    fobj.seek(0)
    counts = {d: sample.count(d.encode()) for d in DELIMS}
    best = max(counts.values())
    if best <= 0:
        return ","
    for d in DELIMS:  # tuple order => comma wins ties
        if counts[d] == best:
            return d
    return ","


def sanitize_key(filename: str) -> str:
    """Storage-key layer sanitization. Input ext must be whitelisted; output is
    always .parquet. Strips traversal, control chars, and anything unsafe."""
    name = str(filename or "")
    low = name.lower()
    if not low.endswith(ALLOWED_INPUT_EXT):
        raise ValueError("unsupported input extension")
    stem = (
        name[: -len(low.rsplit(".", 1)[-1]) - 1]
        if "." in name
        else name
    )
    stem = "".join(c for c in stem if c.isalnum() or c in "._-")
    # Collapse dot-runs to a single dot until stable (single replace can create
    # new '..' sequences: a....b -> a..b -> a.b).
    while ".." in stem:
        stem = stem.replace("..", ".")
    stem = stem.strip(".-_") or "upload"
    return stem[:128] + ".parquet"


class HyperStreamWriter(io.RawIOBase):
    """S3 multipart streaming writer presenting the io.RawIOBase file protocol
    (writable/tell/seekable=False) so pyarrow's ParquetWriter accepts it as a
    file-like sink. On any failure the caller MUST call abort() — incomplete
    multipart uploads keep billing until aborted."""

    def __init__(self, client, bucket, key):
        super().__init__()
        self.client = client
        self.bucket = bucket
        self.key = key
        self.buf = io.BytesIO()
        self.part_number = 1
        self.parts = []
        self.aborted = False
        self.bytes_written = 0
        self.upload_id = client.create_multipart_upload(
            Bucket=bucket, Key=key)["UploadId"]

    # --- io.RawIOBase protocol -------------------------------------------
    def writable(self):
        return True

    def seekable(self):
        return False

    def tell(self):
        return self.bytes_written

    def write(self, b):
        if self.aborted:
            # io.RawIOBase contract: returning fewer bytes than given signals
            # a short write, which pyarrow may misread as partial consumption.
            # Fail loudly instead — run_pass's except path aborts (idempotent)
            # and surfaces this as a genuine error.
            raise IOError('writer aborted')
        n = len(b)
        self.buf.write(b)
        self.bytes_written += n
        if self.buf.tell() >= PART_SIZE:
            self._flush_part()
        return n

    def _flush_part(self):
        if self.buf.tell() == 0:
            return
        self.buf.seek(0)
        resp = self.client.upload_part(
            Bucket=self.bucket, Key=self.key, UploadId=self.upload_id,
            PartNumber=self.part_number, Body=self.buf.read())
        self.parts.append({"ETag": resp["ETag"], "PartNumber": self.part_number})
        self.part_number += 1
        self.buf.seek(0)
        self.buf.truncate(0)

    def close(self):
        if self.closed:
            return
        try:
            if not self.aborted:
                # Finalize failure must NEVER leave orphaned parts billing:
                # this covers both the final part upload and complete — the
                # caller's own except path may not run abort() (the exception
                # propagates directly). abort() is idempotent and also closes
                # the buffer — then re-raise so the failure is still visible
                # to the caller.
                try:
                    self._flush_part()
                    self.client.complete_multipart_upload(
                        Bucket=self.bucket, Key=self.key, UploadId=self.upload_id,
                        MultipartUpload={"Parts": self.parts})
                except Exception:
                    self.abort()
                    raise
        finally:
            try:
                self.buf.close()
            except Exception:
                pass
            super().close()

    def abort(self):
        # R19: an abort FAILURE is operationally significant (orphan parts
        # bill forever) — record it so callers/logs can alert, instead of
        # silently passing. Still never masks the primary exception.
        if self.aborted:
            return
        self.aborted = True
        try:
            self.client.abort_multipart_upload(
                Bucket=self.bucket, Key=self.key, UploadId=self.upload_id)
        except Exception as e:
            import sys
            print(f"[engine] WARN: multipart abort failed for {self.bucket}/{self.key}: "
                  f"{type(e).__name__}", file=sys.stderr)
        try:
            self.buf.close()
        except Exception:
            pass


def _assert_resolved_public(host: str) -> str:
    """Re-validate what a dialer would connect to RIGHT NOW (anti-rebinding).

    validate_endpoint_url() ran earlier in the request; a DNS-rebinding attacker
    can answer public then private. Re-resolving here narrows the window to
    milliseconds and fails the job if the address is not public. It is not a
    substitute for connection pinning, which urllib3 does not expose cleanly.
    """
    return _resolve_all_public(host)


def _job_id_from_filename(filename):
    """Extract the gateway's per-job prefix from an inbound filename.

    src/index.js rewrites the outbound upload name to
    "<job id>-<original stem><ext>". R44 derived that id from the paid
    authorization nonce; R55 replaced it with a GATEWAY-GENERATED 128-bit id
    (crypto.randomUUID() with dashes stripped = 32 hex characters), because a
    payer-controlled 64-bit nonce prefix could collide across jobs.

    That prefix is the ONLY thing distinguishing two concurrent jobs that picked
    the same output path, so it must be recovered here and used to namespace the
    key. Accepts both the current 32-hex form and the legacy 16-hex one.
    Returns '' if the name carries no recognizable prefix.
    """
    stem = str(filename or "").replace("\\", "/").split("/")[-1]
    head = stem.split("-", 1)[0].lower()
    # R57: the gateway emits a GATEWAY-GENERATED 128-bit id -- 32 hex chars
    # (crypto.randomUUID() with dashes stripped). Accepting only 16 silently
    # dropped the prefix for every BYO job, so concurrent conversions could
    # overwrite the same caller-supplied object and serve another customer's
    # data. Accept the full 32-hex form (and keep 16 for any older caller).
    if head and len(head) in (16, 32) and all(c in "0123456789abcdef" for c in head):
        return head
    return ""


def make_client(endpoint_url, access_key, secret_key):
    # R53: delegate to s3_guard, which closes both accepted S3 SSRF gaps at the
    # HTTP layer instead of documenting them:
    #   * DNS rebinding -- it resolves the host ONCE and pins the client to
    #     those validated public addresses. The old inline check resolved again
    #     at dial time, so a name could answer public then private.
    #   * redirects -- urllib3 follows them by default, so a validated public
    #     endpoint could 307 to loopback. The guard disables redirect handling.
    import s3_guard
    return s3_guard.build_client(
        os.environ, endpoint_url, access_key, secret_key)

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/compress")
async def compress(file: UploadFile, target_destination: str = Form(None)):
    started = time.time()
    try:
        # ---- resolve destination -----------------------------------------
        custom = None
        if target_destination:
            try:
                custom = json.loads(target_destination)
            except Exception:
                return JSONResponse(status_code=400, content={
                    "status": "error", "message": "target_destination is not valid JSON."})
            if not isinstance(custom, dict):
                return JSONResponse(status_code=400, content={
                    "status": "error",
                    "message": "target_destination must be a JSON object."})
            missing = [k for k in ("endpoint_url", "bucket_name",
                                   "aws_access_key_id", "aws_secret_access_key")
                       if not custom.get(k)]
            if missing:
                return JSONResponse(status_code=400, content={
                    "status": "error",
                    "message": f"target_destination missing fields: {missing}"})

        if custom:
            # R26: validate BEFORE any socket is opened (the preflight below
            # would otherwise happily dial 127.0.0.1 or 169.254.169.254).
            why = validate_endpoint_url(custom["endpoint_url"])
            if why:
                return JSONResponse(status_code=400, content={
                    "status": "error",
                    "message": f"target_destination endpoint rejected: {why}."})
            # R28: re-check the resolved addresses now. A rebinding host can
            # pass the check above and resolve privately by the time boto3
            # connects; this second look fails the job instead of dialing it.
            try:
                _h = urlparse(custom["endpoint_url"]).hostname
            except Exception:
                _h = None
            if _h:
                why2 = _assert_resolved_public(_h)
                if why2:
                    return JSONResponse(status_code=400, content={
                        "status": "error",
                        "message": f"target_destination endpoint rejected: {why2}."})
            endpoint = custom["endpoint_url"]
            ak, sk = custom["aws_access_key_id"], custom["aws_secret_access_key"]
            bucket = custom["bucket_name"]
            leaf = custom.get("file_path") or file.filename
            # Custom-key sanitization: ALWAYS split into path segments, dropping
            # empty/'.'/traversal ('..') components outright, char-filtering
            # each survivor, capping the final stem at 128, forcing .parquet.
            parts = []
            for seg in str(leaf).replace("\\", "/").split("/"):
                if seg in ("", ".", ".."):
                    continue  # no traversal component survives
                seg = "".join(c for c in seg if c.isalnum() or c in "._-")
                seg = seg.strip(".-_")
                if seg:
                    parts.append(seg)
            stem = parts.pop() if parts else "upload"
            if "." in stem:
                stem = stem[: -(len(stem.rsplit(".", 1)[-1]) + 1)]
            # R52: namespace every key by the job id. The gateway prefixes the
            # inbound filename with the paid authorization nonce (R44), but the
            # BYO path previously preferred the caller's raw file_path, so two
            # customers writing "data.parquet" targeted the SAME object -- one
            # silently overwrote the other and a payer could be served another
            # tenant's file. The caller's path is still honoured, just under a
            # per-job prefix so concurrent jobs cannot collide.
            job_prefix = _job_id_from_filename(file.filename)
            key = ((job_prefix + "/") if job_prefix else "") + \
                  ("/".join(parts) + "/" if parts else "") + stem[:128] + ".parquet"
            internal = False
        else:
            endpoint = os.getenv("R2_ENDPOINT_URL")
            ak = os.getenv("R2_ACCESS_KEY_ID")
            sk = os.getenv("R2_SECRET_ACCESS_KEY")
            bucket = os.getenv("R2_BUCKET_NAME")
            key = "outputs/" + sanitize_key(file.filename)
            internal = True

        if not all([endpoint, ak, sk, bucket]):
            return JSONResponse(status_code=500, content={
                "status": "error", "message": "Engine storage env incomplete."})

        try:
            key = key.replace("\\", "/")
            while key.startswith("/"):
                key = key[1:]
        except Exception:
            pass

        # ---- ENGINE-SIDE BINARY/NUL GUARD (defense in depth; the gateway ----
        #      also sniffs before paid dispatch) -------------------------------
        head = file.file.read(1048576)
        file.file.seek(0)
        if b"\x00" in head or head[:2] in (b"PK", b"\x1f\x8b") \
                or head[:4] == b"%PDF":
            return JSONResponse(status_code=400, content={
                "status": "error",
                "message": "Binary content detected (NUL/archive magic in first MB)."})

        # ---- PRE-FLIGHT HANDSHAKE (before burning compute) ----------------
        try:
            probe = make_client(endpoint, ak, sk)
            # Collision-resistant probe key never overwrites customer objects;
            # finally-guaranteed cleanup leaves nothing behind.
            import uuid
            probe_key = f".preflight/{uuid.uuid4()}.handshake"
            # R19: exercise the FULL permission set the output path needs
            # (create/upload/complete/abort multipart + put/delete), so creds
            # that can only put_object fail here — before compute is bought.
            probe_mpu = probe.create_multipart_upload(
                Bucket=bucket, Key=probe_key)
            try:
                part = probe.upload_part(
                    Bucket=bucket, Key=probe_key,
                    UploadId=probe_mpu["UploadId"], PartNumber=1,
                    Body=b"x402-preflight-probe")
                # Use the ETag returned by upload_part — fabricating one makes
                # real S3-compatible services reject every preflight.
                probe.complete_multipart_upload(
                    Bucket=bucket, Key=probe_key, UploadId=probe_mpu["UploadId"],
                    MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]})
            except Exception:
                # R21: an incomplete probe MPU leaves billable parts — always
                # abort it before re-raising. Abort failure itself rejects
                # preflight (creds lacking s3:AbortMultipartUpload would leave
                # real orphans later).
                try:
                    probe.abort_multipart_upload(
                        Bucket=bucket, Key=probe_key,
                        UploadId=probe_mpu["UploadId"])
                except Exception as abort_err:
                    raise RuntimeError("preflight abort-permission check failed") from abort_err
                raise
            finally:
                # R25(F): always clean up the completed probe object, even if a
                # later probe step raises.
                try:
                    probe.delete_object(Bucket=bucket, Key=probe_key)
                except Exception:
                    pass

            # R22: DEDICATED abort-permission probe — create a second real MPU
            # that exists only to be successfully aborted. Credentials lacking
            # s3:AbortMultipartUpload fail preflight here, before compute.
            abort_probe = probe.create_multipart_upload(Bucket=bucket, Key=probe_key)
            probe.abort_multipart_upload(
                Bucket=bucket, Key=probe_key, UploadId=abort_probe["UploadId"])
        except Exception as e:
            log_diagnostic("preflight", e)  # internal stdout only, redacted
            return JSONResponse(status_code=400, content={
                "status": "error",
                "message": ("Pre-flight validation failed. Target S3 credentials or "
                            "bucket permissions are invalid."),
            })

        # ---- DELIMITER: derived from input extension (.tsv -> tab,
        #      .csv -> comma, .txt -> sniffed from the first 64KB) ----------
        chosen_delimiter = choose_delimiter(file.filename, file.file)

        # ---- stream convert (input sniffing/NUL-guard lives in the gateway;
        #      the engine trusts the gateway's validated stream) --------------
        skipped_columns = []
        rows = 0
        skipped_rows = 0
        drift_fallback = False
        frozen_schema = None

        def run_pass(convert_options):
            """ONE full CSV->Parquet pass over the input stream into a fresh
            S3 multipart upload. Freezes the first batch's schema (recorded in
            the enclosing scope even when the pass fails) and reconciles later
            column-level drift best-effort. On any failure the pass aborts its
            own multipart upload (no orphan parts billing) and re-raises."""
            nonlocal frozen_schema
            stream_writer = HyperStreamWriter(
                make_client(endpoint, ak, sk), bucket, key)
            pq_writer = None
            frozen = None
            p_rows = p_chunks = p_invalid = 0
            p_skipped = []

            def skip_invalid_row(row):
                # Malformed / column-count-drift rows: skip and count so a
                # mid-file drift cannot kill the whole paid stream.
                nonlocal p_invalid
                p_invalid += 1
                return "skip"

            try:
                reader = pv.open_csv(
                    file.file,
                    # Block size is env-tunable ONLY so tests can exercise genuine
                    # cross-block type drift; production default 64 MiB.
                    read_options=pv.ReadOptions(
                        block_size=int(os.getenv(
                            "CSV_BLOCK_SIZE", str(64 * 1024 * 1024))),
                        use_threads=True),
                    parse_options=pv.ParseOptions(
                        newlines_in_values=False,
                        delimiter=chosen_delimiter,
                        invalid_row_handler=skip_invalid_row),
                    convert_options=convert_options,
                )
                for batch in reader:
                    table = pa.Table.from_batches([batch])

                    if pq_writer is None:
                        frozen = table.schema
                        pq_writer = pq.ParquetWriter(
                            stream_writer, frozen,
                            compression="zstd", compression_level=3,
                            use_dictionary=True, write_batch_size=100_000,
                            data_page_version="2.0")
                    elif table.schema != frozen:
                        # SCHEMA DRIFT (best-effort reconciliation): drop unknown
                        # extra columns; safe-cast known ones, null-filling cast
                        # failures. Column-COUNT drift rows never reach this
                        # path: invalid_row_handler skips+counts them upstream
                        # (skipped_rows).
                        names_frozen = set(frozen.names)
                        dropped = [n for n in table.schema.names
                                   if n not in names_frozen]
                        if dropped:
                            table = table.drop_columns(dropped)
                            p_skipped.extend(dropped)
                        cols = []
                        for field in frozen:
                            if field.name in table.column_names:
                                col = table.column(field.name)
                                if col.type != field.type:
                                    try:
                                        col = pc.cast(col, field.type, safe=True)
                                    except (pa.ArrowInvalid,
                                            pa.ArrowNotImplementedError):
                                        col = pa.nulls(col.length(),
                                                       type=field.type)
                                        if field.name not in p_skipped:
                                            p_skipped.append(field.name)
                                cols.append(col)
                            else:
                                cols.append(pa.nulls(table.num_rows,
                                                     type=field.type))
                        table = pa.Table.from_arrays(
                            [c.combine_chunks() if isinstance(c, pa.ChunkedArray)
                             else c for c in cols], schema=frozen)

                    pq_writer.write_table(table)
                    p_rows += table.num_rows
                    p_chunks += 1
                    if p_chunks % GC_EVERY == 0:
                        gc.collect()

                if pq_writer is None:
                    stream_writer.abort()
                    return None  # nothing parseable
                pq_writer.close()
                stream_writer.close()
                return p_rows, p_chunks, p_skipped, p_invalid
            except Exception:
                # Orphan multipart uploads bill forever — ALWAYS abort on failure.
                # Abort-first prevents ParquetWriter.close from completing a
                # partial object; abort is idempotent.
                stream_writer.abort()
                try:
                    if pq_writer:
                        pq_writer.close()
                except Exception:
                    pass  # close-after-abort can't complete anything; best-effort dispose
                raise
            finally:
                frozen_schema = frozen

        first_error = None
        in_fallback = False
        res = None
        try:
            res = run_pass(pv.ConvertOptions(
                strings_can_be_null=True, auto_dict_encode=True,
                auto_dict_max_cardinality=512, include_missing_columns=False))
        except (pa.ArrowInvalid, pa.ArrowTypeError) as e:
            # Mid-file TYPE drift: ONE automatic lossless all-string re-read.
            # A second drift failure inside the fallback propagates to the
            # clean 500 below (fallback is attempted exactly once).
            drift_fallback = True
            in_fallback = True
            first_error = e
            file.file.seek(0)
            try:
                res = run_pass(pv.ConvertOptions(
                    column_types={name: pa.string() for name in frozen_schema.names}
                    if frozen_schema else {},
                    strings_can_be_null=True, include_missing_columns=True,
                    auto_dict_encode=False))
            except (pa.ArrowInvalid, pa.ArrowTypeError) as fe:
                log_diagnostic("fallback", fe)  # internal stdout only, redacted
                # If the FIRST pass failed BEFORE parsing any batch
                # (frozen_schema was None), the fallback re-ran with identical
                # all-string options and can only re-fail identically — so the
                # generic 500 would lose the real cause. Surface the masked
                # original error instead.
                if frozen_schema is None and first_error is not None:
                    # R34: the detail goes to the redacted internal log only.
                    log_diagnostic("pre_parse_failure", first_error)
                    return JSONResponse(status_code=500, content={
                        "status": "error",
                        "message": GENERIC_INTERNAL_ERROR})
                raise

        if res is None:
            if in_fallback and frozen_schema is None and first_error is not None:
                # Fallback parsed no rows AND the first pass failed pre-parse.
                # R34: log the redacted cause internally, return a generic
                # message -- exception text in a response body is a leak channel.
                log_diagnostic("pre_parse_no_rows", first_error)
                return JSONResponse(status_code=500, content={
                    "status": "error",
                    "message": GENERIC_INTERNAL_ERROR})
            return JSONResponse(status_code=400, content={
                "status": "error", "message": "No parseable CSV rows found."})
        rows, _chunks, pass_skipped, pass_invalid = res
        skipped_columns.extend(pass_skipped)
        skipped_rows += pass_invalid

        duration_s = round(time.time() - started, 2)
        result = {
            "status": "success",
            "output_bucket": bucket,
            "output_key": key,
            "rows": rows,
            "skipped_rows": int(skipped_rows),
            "drift_fallback": drift_fallback,
            "skipped_columns": sorted(set(skipped_columns)),
            "duration_s": duration_s,
            "estimated_cost_usd": round(duration_s * CPU_RATE_PER_HR / 3600, 6),
        }
        if internal:
            client = make_client(endpoint, ak, sk)
            result["download_url"] = client.generate_presigned_url(
                "get_object", Params={"Bucket": bucket, "Key": key},
                ExpiresIn=86400)
            result["warning"] = "auto-deletes in 24 hours via bucket lifecycle rule"
        return result

    except Exception as e:
        log_diagnostic("convert", e)  # internal stdout only, redacted
        return JSONResponse(status_code=500, content={
            "status": "error", "message": "Conversion failed."})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
