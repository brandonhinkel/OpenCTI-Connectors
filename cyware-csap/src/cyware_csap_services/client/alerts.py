"""Cyware CSAP Alerts API client."""

from __future__ import annotations

from typing import Any

from .base_api import BaseCywareClient

_LIST_ALERT_ENDPOINT = "csap/v1/list_alert/"
_ALERT_DETAIL_ENDPOINT = "csap/v1/get_alert_detail/{short_id}"
_ALERT_PDF_ENDPOINT = "csap/v1/alert-pdf/{alert_id}/"


class AlertsAPI(BaseCywareClient):
    """Client methods for Cyware CSAP alert (card) endpoints."""

    def list_alerts(
        self,
        start_time: int | None = None,
        end_time: int | None = None,
        page: int = 1,
        page_size: int = 50,
        category_ids: list[str] | None = None,
        tlp_filter: list[str] | None = None,
    ) -> dict[str, Any]:
        """List published alerts with optional time and filter constraints.

        start_time and end_time are UNIX timestamps. Both require status=PUBLISHED
        (enforced by this method — the Cyware API ignores them otherwise).

        Returns: {"count": int, "data": [{"short_id", "title", "status", "published_time"}]}
        """
        params: dict[str, Any] = {
            "status": "PUBLISHED",
            "page": page,
            "page_size": page_size,
        }
        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        if category_ids:
            params["category_id"] = ",".join(category_ids)
        if tlp_filter:
            params["tlp"] = ",".join(tlp_filter)

        return self._get(_LIST_ALERT_ENDPOINT, **params)

    def get_alert_detail(self, short_id: str) -> dict[str, Any]:
        """Fetch full alert detail including indicators, metadata, and attachments."""
        return self._get(_ALERT_DETAIL_ENDPOINT.format(short_id=short_id))

    def get_alert_pdf(self, alert_id: str) -> bytes | None:
        """Download alert PDF attachment. Returns bytes or None if unavailable.

        Phase 6 feature — placeholder implementation.
        """
        # TODO Phase 6: implement binary download and OpenCTI file attachment
        return None
