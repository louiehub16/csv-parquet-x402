"""Engine tests: in-memory FakeS3, no network, no real pyarrow file I/O beyond
BytesIO. Covers sanitize_key traversal, 10k-row happy path, .tsv delimiter
handling, preflight rejection, NUL-byte rejection at the API boundary, type
drift survival (string fallback), and column-count drift survival (skipped
rows accounting)."""
import io
import json
import os
import sys
import types
from unittest import mock

import pytest
import pyarrow.parquet as pq

# ---------------------------------------------------------------------------
# FakeS3 must exist BEFORE main imports boto3.client — patch boto3 first.
# ---------------------------------------------------------------------------
class FakeS3:
    def __init__(self, fail_writes=False):
        self.objects = {}
        self.multipart = {}
        self.counter = 0
        self.fail_writes = fail_writes

    def put_object(self, Bucket, Key, Body=b""):
        if self.fail_writes:
            raise RuntimeError("bucket denied; creds leaked? AKIAEXAMPLE0000")
        self.objects[(Bucket, Key)] = bytes(Body or b"")

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)

    def create_multipart_upload(self, Bucket, Key):
        if self.fail_writes:
            raise RuntimeError("bucket denied; creds leaked? AKIAEXAMPLE0000")
        self.counter += 1
        self.multipart[self.counter] = {"Bucket": Bucket, "Key": Key, "parts": {}}
        return {"UploadId": self.counter}

    def upload_part(self, Bucket, Key, UploadId, PartNumber, Body):
        m = self.multipart[UploadId]
        assert (m["Bucket"], m["Key"]) == (Bucket, Key)
        etag = f"etag{UploadId}-{PartNumber}"
        m["parts"][PartNumber] = bytes(Body)
        m.setdefault("etags", {})[PartNumber] = etag
        return {"ETag": etag}

    def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
        if UploadId not in self.multipart:
            # R19 preflight probe: a probe MPU completed with a synthetic part.
            self.objects[(Bucket, Key)] = b"probe"
            return {"ETag": "final"}
        m = self.multipart.pop(UploadId)
        # R20: validate each supplied ETag matches what upload_part returned —
        # fabricated ETags mean the client never talked to this store.
        for p in MultipartUpload["Parts"]:
            expected = m.get("etags", {}).get(p["PartNumber"])
            if p["PartNumber"] in m["parts"] and expected and p["ETag"] != expected:
                raise AssertionError(
                    f"fabricated ETag for part {p['PartNumber']}: {p['ETag']} != {expected}")
        data = b"".join(m["parts"].get(p["PartNumber"], b"") for p in MultipartUpload["Parts"])
        self.objects[(Bucket, Key)] = data
        return {"ETag": "final"}

    def abort_multipart_upload(self, Bucket, Key, UploadId):
        self.multipart.pop(UploadId, None)

    def generate_presigned_url(self, *a, **k):
        return "https://fake/presigned"

FAKE = FakeS3()

import boto3  # noqa: E402
# R53: s3_guard.build_client() constructs its client via
# boto3.session.Session().client(...) -- NOT boto3.client() -- so patching
# boto3.client alone let the guard build a REAL client that dialled the
# endpoint (405 from example.com). Patch the seam the guard actually uses,
# and keep boto3.client patched for the legacy path.
boto3.client = lambda *a, **k: FAKE
try:
    from boto3.session import Session as _BotoSession  # noqa: E402
    _BotoSession.client = lambda self, *a, **k: FAKE
except Exception:  # pragma: no cover - boto3 always exposes the session
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as engine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(engine.app)

# R74: shared fake token the autouse fixture configures and _post() presents.
ENGINE_TEST_KEY = "test-engine-token-not-a-real-secret"


@pytest.fixture(autouse=True)
def reset_fake(monkeypatch):
    FAKE.objects.clear()
    FAKE.multipart.clear()
    FAKE.fail_writes = False
    # R74: /v1/compress now requires the gateway bearer token and FAILS CLOSED
    # when ENGINE_API_KEY is unset, so the suite must supply one or every request
    # is refused at the auth gate before reaching any asserted path.
    monkeypatch.setenv("ENGINE_API_KEY", ENGINE_TEST_KEY)
    # Internal-storage env for the default path (boto3 is faked; values inert)
    # R53: s3_guard REQUIRES the endpoint host to resolve to public addresses,
    # so a non-resolvable name is rejected before any S3 call. example.com is
    # used because it resolves publicly; boto3 itself is faked below.
    monkeypatch.setenv("R2_ENDPOINT_URL", "https://example.com")
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "AKIAFAKEACCESS1234")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "fake-secret-key-000")
    monkeypatch.setenv("R2_BUCKET_NAME", "test-bucket")


def test_sanitize_key_traversal():
    out = engine.sanitize_key("../../etc/passwd.csv")
    assert out.endswith(".parquet")
    assert "/" not in out and "\\" not in out and ".." not in out

def test_sanitize_key_wrong_ext():
    with pytest.raises(ValueError):
        engine.sanitize_key("evil.exe")

def test_sanitize_key_unicode_and_control():
    out = engine.sanitize_key("re\u0000po\u001brt .csv")
    assert "\u0000" not in out and "\u001b" not in out


def _post(csv_bytes, name="data.csv", dest=None):
    files = {"file": (name, io.BytesIO(csv_bytes), "text/csv")}
    data = {}
    if dest is not None:
        data["target_destination"] = json.dumps(dest)
    # R74: the engine is gateway-only, so present the bearer token the fixture
    # configured. Without it the request 503s at the auth gate.
    return client.post("/v1/compress", files=files, data=data,
                       headers={"Authorization": "Bearer " + ENGINE_TEST_KEY})


def test_happy_path_10k_rows_internal():
    rows = "id,name,score\n" + "".join(f"{i},row{i},{i/10}\n" for i in range(10000))
    r = _post(rows.encode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["rows"] == 10000
    assert body["download_url"].startswith("https://fake/")
    assert "warning" in body  # internal => 24h retention warning present
    # parquet magic bytes actually landed in the fake bucket
    key = ("test-bucket", body["output_key"])
    assert FAKE.objects[key][:4] == b"PAR1"


def test_tsv_delimiter():
    # Tab-separated input must be parsed with '\t' (derived from the .tsv
    # extension), producing a 3-column parquet output.
    n = 50
    tsv = "id\tname\tscore\n" + "".join(f"{i}\trow{i}\t{i}\n" for i in range(n))
    r = _post(tsv.encode(), name="data.tsv")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["rows"] == n
    key = ("test-bucket", body["output_key"])
    table = pq.read_table(io.BytesIO(FAKE.objects[key]))
    assert table.column_names == ["id", "name", "score"]
    assert table.num_rows == n


def test_bad_custom_dest_preflight_rejection():
    FAKE.fail_writes = True
    dest = {"endpoint_url": "https://example.com", "bucket_name": "nope",
            "aws_access_key_id": "AKIAEXAMPLE0000", "aws_secret_access_key": "shhh"}
    r = _post(b"a,b\n1,2\n", dest=dest)
    assert r.status_code == 400
    assert "Pre-flight validation failed" in r.json()["message"]
    assert 'AKIAEXAMPLE0000' not in r.text


def test_nul_byte_payload_rejected():
    r = _post(b'a,b\n1,\x002\n')
    assert r.status_code == 400
    assert 'Binary content detected' in r.json()['message']
    assert len(FAKE.multipart) == 0


def test_column_count_drift_skipped_and_survives():
    # EXTRA columns appearing mid-file are handled by ParseOptions'
    # invalid_row_handler: drift rows are SKIPPED and counted, the stream
    # completes 200, and NO orphan multipart upload is left billing.
    part1 = "".join(f"{i},alpha\n" for i in range(500))
    part2 = "".join(f"{i},beta,extra{i}\n" for i in range(500, 1200))
    csv = "id,name\n" + part1 + part2
    r = _post(csv.encode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["rows"] == 500          # only the well-formed rows counted
    assert body["skipped_rows"] > 0     # drift rows accounted, not silent
    assert len(FAKE.multipart) == 0, "orphan multipart left open after parse failure!"


def test_type_drift_survives_via_string_fallback(monkeypatch):
    # Shrink the CSV block size so the numeric->text label change genuinely
    # spans two inference blocks (production default 64MB would parse the
    # whole fixture as one block and never see drift).
    monkeypatch.setenv("CSV_BLOCK_SIZE", "4096")
    part1 = "".join(f"{i},123\n" for i in range(800))   # numeric label -> int inference
    part2 = "".join(f"{i},abc{i}\n" for i in range(800, 1500))  # then text -> ArrowInvalid
    csv = "id,label\n" + part1 + part2
    r = _post(csv.encode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "success"
    assert body["rows"] == 1500
    assert body["drift_fallback"] is True


def test_orphan_abort_on_engine_failure():
    # Simulate a finalize failure on the REAL output upload — but NOT on the
    # preflight probe (whose key lives under .preflight/), so we reach the
    # engine's stream path and exercise orphan cleanup there.
    orig = FakeS3.complete_multipart_upload
    def boom(self, Bucket, Key, UploadId, MultipartUpload):
        if Key.startswith(".preflight/"):
            self.multipart.pop(UploadId, None)  # probe completes normally
            return {"ETag": "probe"}
        # Abort-first ordering (R19): a real S3 backend rejects complete on an
        # already-aborted upload — no partial object may exist after failure.
        raise RuntimeError("simulated finalize failure")
    FakeS3.complete_multipart_upload = boom
    try:
        r = _post(b"x,y\n1,2\n")
        assert r.status_code == 500
        # the failed upload must have been ABORTED, not left billing
        assert len(FAKE.multipart) == 0, "orphan multipart upload left open!"
        # and NO completed output object may exist (the .handshake probe is
        # cleaned up during preflight, so the bucket must be completely empty)
        assert len(FAKE.objects) == 0, (
            "completed/partial output object exists despite engine failure!")
    finally:
        FakeS3.complete_multipart_upload = orig
