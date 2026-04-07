"""HMAC-SHA1 authentication for Cyware CSAP API.

Signing scheme confirmed from official Cyware sample code:
  - string_to_sign = "{access_id}\\n{expires}"
  - signature = base64(hmac_sha1(secret_key, string_to_sign))
  - Three query params added to every request: AccessID, Expires, Signature
"""

import base64
import hashlib
import hmac
import time
import urllib.parse

EXPIRY_MARGIN_SECONDS = 20


def generate_signature(access_id: str, secret_key: str, expires: int) -> str:
    """Compute the HMAC-SHA1 base64-encoded signature for a CSAP request."""
    to_sign = "{}\n{}".format(access_id, expires)
    hashed = hmac.new(
        secret_key.encode("utf-8"),
        to_sign.encode("utf-8"),
        hashlib.sha1,
    )
    return base64.b64encode(hashed.digest()).decode("utf-8")


def build_auth_params(access_id: str, secret_key: str) -> dict:
    """Return the three auth query parameters to merge into every CSAP request."""
    expires = int(time.time()) + EXPIRY_MARGIN_SECONDS
    return {
        "Expires": expires,
        "AccessID": access_id,
        "Signature": generate_signature(access_id, secret_key, expires),
    }


def build_url(base_url: str, endpoint: str, params: dict) -> str:
    """Construct a full CSAP API URL with all query parameters encoded.

    base_url must end with '/'. endpoint must NOT start with '/'.

    Example:
        build_url("https://csap-01.cyware.com/api/", "csap/v1/list_alert/", {...})
        → "https://csap-01.cyware.com/api/csap/v1/list_alert/?AccessID=...&..."
    """
    return base_url + endpoint + "?" + urllib.parse.urlencode(params, doseq=True)
