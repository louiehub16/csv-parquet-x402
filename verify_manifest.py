#!/usr/bin/env python3
"""Verify the x402 discovery surface of a CSV-to-Parquet Stream Compressor deployment.

Usage:
    python verify_manifest.py <domain>

    python verify_manifest.py csv-parquet.YOURDOMAIN.workers.dev
    python verify_manifest.py https://csv-parquet.example.com

Checks:
  1. GET /.well-known/x402.json  -> 200 + strict-parseable JSON
  2. GET /llms.txt               -> 200 + non-empty text
  3. GET /openapi.json           -> 200 + strict-parseable JSON
  4. Mandatory x402.json fields present (top-level + nested protocol block)
  5. A >= 10GB user-supplied-destination tier exists
     (range_min_bytes == 10737418240, storage_target user_supplied*)
  6. Tier byte boundaries are monotonic ascending with no gaps/overlaps

Exit code 0 if every check passes, otherwise 1.

Dependencies: stdlib + requests only.
"""

import json
import sys

import requests

TIMEOUT = 20

TIER_10GB = 10 * 1024 * 1024 * 1024  # 10737418240

MANDATORY_TOP_LEVEL = [
    "service_id",
    "display_name",
    "tagline",
    "description",
    "categories",
    "keywords",
    "capabilities",
    "pricing_matrix",
    "x402",
    "endpoints",
    "developer",
]

MANDATORY_X402 = {
    "version": 2,
    "network": "eip155:8453",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0x4856127fd489CE7FEC456381565f56e3924381bE",
    "scheme": "exact",
}

results = []  # (check_name, ok: bool, detail: str)


def record(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print("[PASS] %-46s %s" % (name, detail) if ok else "[FAIL] %-46s %s" % (name, detail))


def normalize_base(domain):
    domain = domain.strip().rstrip("/")
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    return domain


def fetch_json(base, path):
    url = base + path
    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return None, False, "GET %s raised %s" % (url, exc.__class__.__name__)
    if resp.status_code != 200:
        return None, False, "GET %s -> HTTP %d" % (url, resp.status_code)
    try:
        return json.loads(resp.text), True, "GET %s -> 200, parsed JSON (%d bytes)" % (url, len(resp.content))
    except ValueError as exc:
        return None, False, "GET %s -> 200 but not strict JSON (%s)" % (url, exc)


def main():
    if len(sys.argv) != 2:
        print("usage: python verify_manifest.py <domain>")
        return 1
    base = normalize_base(sys.argv[1])

    # --- 1. /.well-known/x402.json -------------------------------------
    manifest, ok, detail = fetch_json(base, "/.well-known/x402.json")
    record("x402.json fetch+parse", ok, detail)

    # --- 2. /llms.txt ---------------------------------------------------
    try:
        r_llms = requests.get(base + "/llms.txt", timeout=TIMEOUT)
        llms_ok = r_llms.status_code == 200 and len(r_llms.text.strip()) > 0
        record(
            "llms.txt fetch",
            llms_ok,
            "HTTP %d, %d chars%s"
            % (
                r_llms.status_code,
                len(r_llms.text),
                "" if r_llms.status_code == 200 else " (expected 200)",
            ),
        )
    except requests.RequestException as exc:
        record("llms.txt fetch", False, str(exc))

    # --- 3. /openapi.json -------------------------------------------------
    openapi, ok, detail = fetch_json(base, "/openapi.json")
    record("openapi.json fetch+parse", ok, detail)
    if openapi is not None:
        has_paths = isinstance(openapi.get("paths"), dict) and "/v1/compress" in openapi["paths"]
        record("openapi paths include /v1/compress", has_paths, "" if has_paths else "missing")

    if manifest is None:
        print("\nRESULT: FAIL — x402.json unavailable; skipping deep checks")
        return 1

    # --- 4. Mandatory manifest fields ------------------------------------
    missing_top = [k for k in MANDATORY_TOP_LEVEL if k not in manifest]
    record("manifest top-level mandatory fields", not missing_top,
           "all %d present" % len(MANDATORY_TOP_LEVEL) if not missing_top else "missing: %s" % ", ".join(missing_top))

    x402_block = manifest.get("x402") or {}
    bad_x402 = []
    for key, expected in MANDATORY_X402.items():
        actual = x402_block.get(key)
        if isinstance(expected, str):
            if str(actual).lower() != expected.lower():
                bad_x402.append("%s=%r" % (key, actual))
        elif actual != expected:
            bad_x402.append("%s=%r (want %r)" % (key, actual, expected))
    pricing_note_present = bool(x402_block.get("pricing_note"))
    if not pricing_note_present:
        bad_x402.append("pricing_note missing")
    record("manifest x402 protocol block", not bad_x402,
           "version/network/asset/payTo/scheme + pricing_note OK" if not bad_x402 else "; ".join(bad_x402))

    endpoints = manifest.get("endpoints") or {}
    ep_ok = all(str(endpoints.get(k, "")).strip() for k in ("gateway_root", "compress", "llms", "openapi", "mcp_config"))
    record("manifest endpoints block", ep_ok, "gateway_root=%s" % endpoints.get("gateway_root"))

    dev_ok = bool((manifest.get("developer") or {}).get("support_contact"))
    record("manifest developer.support_contact", dev_ok, str((manifest.get("developer") or {}).get("support_contact")))

    caps = manifest.get("capabilities") or {}
    caps_ok = caps.get("streaming") is True and caps.get("supported_input_formats") == ["csv", "tsv", "txt"]
    record("manifest capabilities", caps_ok, "streaming=true formats=csv/tsv/txt" if caps_ok else str(caps))

    # --- 5 & 6. Pricing tiers --------------------------------------------
    tiers = (manifest.get("pricing_matrix") or {}).get("tiers") or []
    tier_10gb = [
        t for t in tiers
        if t.get("range_min_bytes") == TIER_10GB
        and str(t.get("storage_target", "")).startswith("user_supplied")
    ]
    record("10GB user_supplied_destination tier exists", bool(tier_10gb),
           "range_min_bytes==%d storage_target=user_supplied*" % TIER_10GB if tier_10gb else "not found among %d tiers" % len(tiers))

    monotonic = bool(tiers)
    boundary_detail = []
    try:
        for i, t in enumerate(tiers):
            is_final = i == len(tiers) - 1
            hi = t.get("range_max_bytes")
            # Non-final tiers: range_max_bytes MUST be an int > 0 (only the
            # final tier may have null/absent range_max_bytes).
            if not is_final and (isinstance(hi, bool) or not isinstance(hi, int) or hi <= 0):
                monotonic = False
                if hi is None:
                    boundary_detail.append("tier%d non-final tier missing range_max_bytes" % (i + 1))
                else:
                    boundary_detail.append("tier%d non-final tier range_max_bytes=%r must be int > 0" % (i + 1, hi))
                break
            # Chaining (i > 0): this tier's range_min_bytes must exactly equal
            # the previous tier's finite range_max_bytes (no gaps, no overlaps).
            if i > 0:
                prev_hi = tiers[i - 1].get("range_max_bytes")
                lo = t.get("range_min_bytes")
                if lo != prev_hi:
                    monotonic = False
                    boundary_detail.append(
                        "tier%d range_min_bytes=%r must exactly equal previous tier range_max_bytes=%r"
                        % (i + 1, lo, prev_hi))
                    break
    except Exception as exc:
        monotonic = False
        boundary_detail.append("tier boundary check exception: %s" % exc.__class__.__name__)
    record("tier byte boundaries monotonic ascending", monotonic,
           "0->104857600->10737418240->107374182400->1099511627776->unbounded"
           if monotonic else "; ".join(boundary_detail) or "no tiers found")

    # --- Verdict ----------------------------------------------------------
    failed = [r for r in results if not r[1]]
    print("\n%d/%d checks passed" % (len(results) - len(failed), len(results)))
    print("RESULT: " + ("PASS" if not failed else "FAIL (%d)" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
