"""Base Cyware CSAP API client with HMAC authentication and retry logic."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import requests

from cyware_csap_services.utils.auth import build_auth_params, build_url

if TYPE_CHECKING:
    from cyware_csap_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 2  # seconds


class BaseCywareClient:
    """Authenticated HTTP client for the Cyware CSAP REST API."""

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
    ) -> None:
        self.config = config
        self.helper = helper
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    @property
    def _base_url(self) -> str:
        return self.config.cyware.base_url

    @property
    def _access_id(self) -> str:
        return self.config.cyware.access_id.get_secret_value()

    @property
    def _access_secret(self) -> str:
        return self.config.cyware.access_secret.get_secret_value()

    def _get_bytes(self, endpoint: str, **params: Any) -> bytes:
        """Make an authenticated GET request and return raw response bytes.

        Used for binary downloads such as PDF exports.
        Raises on non-retryable errors; returns bytes on success.
        """
        auth = build_auth_params(self._access_id, self._access_secret)
        url = build_url(self._base_url, endpoint, {**params, **auth})

        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = self._session.get(
                    url,
                    timeout=60,
                    headers={"Accept": "application/pdf"},
                )
            except requests.RequestException as exc:
                last_exc = exc
                self.helper.log_warning(
                    f"[API] Network error on attempt {attempt}/{_MAX_RETRIES}: {exc}"
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF_BASE ** attempt)
                continue

            if response.status_code == 200:
                return response.content

            if response.status_code in _RETRYABLE_STATUS_CODES:
                wait = _RETRY_BACKOFF_BASE ** attempt
                if response.status_code == 429:
                    try:
                        wait = int(response.headers.get("Retry-After", wait))
                    except (ValueError, TypeError):
                        pass
                self.helper.log_warning(
                    f"[API] HTTP {response.status_code} on attempt {attempt}/{_MAX_RETRIES} "
                    f"for '{endpoint}', retrying in {wait}s"
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(wait)
                continue

            self.helper.log_error(
                f"[API] HTTP {response.status_code} for endpoint '{endpoint}': "
                f"{response.text[:300]}"
            )
            response.raise_for_status()

        if last_exc:
            raise last_exc
        raise requests.HTTPError(
            f"All {_MAX_RETRIES} retries exhausted for endpoint: {endpoint}"
        )

    def _get(self, endpoint: str, **params: Any) -> dict:
        """Make an authenticated GET request to the CSAP API.

        endpoint: path without leading slash, e.g. "csap/v1/list_alert/"
        **params: additional query parameters; auth params are merged automatically.

        Retries up to _MAX_RETRIES times on transient errors (5xx, 429, network).
        Raises on non-retryable 4xx errors.
        """
        auth = build_auth_params(self._access_id, self._access_secret)
        url = build_url(self._base_url, endpoint, {**params, **auth})

        last_exc: Exception | None = None

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = self._session.get(url, timeout=30)
            except requests.RequestException as exc:
                last_exc = exc
                self.helper.log_warning(
                    f"[API] Network error on attempt {attempt}/{_MAX_RETRIES}: {exc}"
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF_BASE ** attempt)
                continue

            if response.status_code == 200:
                data = response.json()
                self.helper.log_debug(
                    f"[API] {endpoint} → {str(data)[:1000]}"
                )
                return data

            if response.status_code in _RETRYABLE_STATUS_CODES:
                wait = _RETRY_BACKOFF_BASE ** attempt
                if response.status_code == 429:
                    try:
                        wait = int(response.headers.get("Retry-After", wait))
                    except (ValueError, TypeError):
                        pass
                self.helper.log_warning(
                    f"[API] HTTP {response.status_code} on attempt {attempt}/{_MAX_RETRIES} "
                    f"for '{endpoint}', retrying in {wait}s"
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(wait)
                continue

            # Non-retryable client error
            self.helper.log_error(
                f"[API] HTTP {response.status_code} for endpoint '{endpoint}': "
                f"{response.text[:300]}"
            )
            response.raise_for_status()

        if last_exc:
            raise last_exc
        raise requests.HTTPError(
            f"All {_MAX_RETRIES} retries exhausted for endpoint: {endpoint}"
        )
