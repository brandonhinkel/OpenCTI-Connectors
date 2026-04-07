"""
Cyware CSAP API Diagnostic Probe
---------------------------------
Run this on the whitelisted server to gather field structure information
needed before implementing the OpenCTI connector.

Fill in the three variables below, then run:
    python3 probe_api.py

Output is intentionally minimal for manual relay.
"""

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import requests

# ── CONFIGURE THESE ──────────────────────────────────────────────────────────
BASE_URL   = ""   # Must end with /  e.g. "https://csap-01.cyware.com/api/"
ACCESS_ID  = ""
SECRET_KEY = ""
# ─────────────────────────────────────────────────────────────────────────────

EXPIRY_MARGIN = 20  # seconds


def signature(access_id, secret_key, expires):
    to_sign = "{}\n{}".format(access_id, expires)
    hashed = hmac.new(secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1)
    return base64.b64encode(hashed.digest()).decode("utf-8")


def get(endpoint, **params):
    """Make an authenticated GET request. endpoint must NOT start with /."""
    expires = int(time.time()) + EXPIRY_MARGIN
    params["Expires"]   = expires
    params["AccessID"]  = ACCESS_ID
    params["Signature"] = signature(ACCESS_ID, SECRET_KEY, expires)
    url = BASE_URL + endpoint + "?" + urllib.parse.urlencode(params, doseq=True)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def compact(value):
    """One-line JSON for small relay."""
    return json.dumps(value, separators=(",", ":"))


def probe_field(alert_detail, field):
    """Return the field value only if it is non-null and non-empty."""
    v = alert_detail.get(field)
    if v is None:
        return None
    if isinstance(v, (list, dict)) and not v:
        return None
    return v


# Fields whose structure is unknown from the swagger (all had null/[] examples)
UNKNOWN_FIELDS = [
    "tactic_technique_pairs_data",
    "threat_actor",
    "targeted_sector",
    "kill_chain_phase",
    "severity",
    "confidence",
    "credibility",
    "cyber_threat_method",
    "threat_method",
    "detectionmethod",
    "event",
]


def main():
    print("=== 1. CONNECTIVITY ===")
    try:
        r = get("csap/v1/test_connectivity/")
        print("OK:", compact(r))
    except Exception as e:
        print("FAILED:", e)
        return

    print()
    print("=== 2. SCANNING ALERTS FOR UNKNOWN FIELDS ===")
    print("(checking up to 5 pages of 20 alerts each)")

    found = {f: None for f in UNKNOWN_FIELDS}
    checked = 0

    for page in range(1, 6):
        try:
            listing = get(
                "csap/v1/list_alert/",
                status="PUBLISHED",
                page=page,
                page_size=20,
            )
        except Exception as e:
            print(f"list_alert page {page} failed: {e}")
            break

        alerts = listing.get("data", [])
        if not alerts:
            print(f"No alerts on page {page}, stopping.")
            break

        total = listing.get("count", "?")
        print(f"Page {page}: {len(alerts)} alerts (total={total})")

        for summary in alerts:
            short_id = summary.get("short_id")
            if not short_id:
                continue

            try:
                detail = get(f"csap/v1/get_alert_detail/{short_id}")
            except Exception as e:
                print(f"  detail {short_id} failed: {e}")
                continue

            checked += 1
            for field in UNKNOWN_FIELDS:
                if found[field] is not None:
                    continue
                val = probe_field(detail, field)
                if val is not None:
                    found[field] = val

            # Stop early if all fields found
            if all(v is not None for v in found.values()):
                print("All unknown fields resolved, stopping early.")
                break

        else:
            # Continue to next page
            continue
        break  # inner break propagated

    print()
    print("=== 3. RESULTS ===")
    print(f"Alerts checked: {checked}")
    print()
    for field, value in found.items():
        if value is not None:
            print(f"FOUND  {field}:")
            print(f"  {compact(value)}")
        else:
            print(f"EMPTY  {field}: (not populated in any checked alert)")

    print()
    print("=== 4. INDICATOR FIELD NAMES ===")
    print("(checking one alert detail for top-level indicator keys)")
    try:
        listing = get("csap/v1/list_alert/", status="PUBLISHED", page=1, page_size=1)
        short_id = listing["data"][0]["short_id"]
        detail = get(f"csap/v1/get_alert_detail/{short_id}")
        indicators = detail.get("indicators", {})
        print("Indicator types present:", list(indicators.keys()))
        for ioc_type, bucket in indicators.items():
            if isinstance(bucket, dict):
                bl = bucket.get("blacklisted", [])
                wl = bucket.get("whitelisted", [])
                print(f"  {ioc_type}: blacklisted={len(bl)}, whitelisted={len(wl)}")
                if bl:
                    print(f"    example blacklisted: {bl[0]}")
            elif isinstance(bucket, list):
                print(f"  {ioc_type} (flat list): count={len(bucket)}")
                if bucket:
                    print(f"    example: {bucket[0]}")
    except Exception as e:
        print("indicator probe failed:", e)


if __name__ == "__main__":
    main()
