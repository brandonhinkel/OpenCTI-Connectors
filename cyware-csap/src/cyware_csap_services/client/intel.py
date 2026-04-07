"""Cyware CSAP Intel API client."""

from __future__ import annotations

from typing import Any

from .base_api import BaseCywareClient

_LIST_INTEL_ENDPOINT = "csap/v1/list_intel_reported/"
_INTEL_DETAIL_ENDPOINT = "csap/v1/get_intel_detail/{incident_id}"


class IntelAPI(BaseCywareClient):
    """Client methods for Cyware CSAP member-submitted intel endpoints."""

    def list_intel(
        self,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """List member-submitted intel reports (newest first).

        Note: this endpoint has no start_time filter. State tracking is handled
        by the IntelImporter using count comparison and processed ID sets.

        Returns: {"count": int, "data": [{"incident_id", "title", "description", "category"}]}
        """
        return self._get(
            _LIST_INTEL_ENDPOINT,
            page=page,
            page_size=page_size,
        )

    def get_intel_detail(self, incident_id: str) -> dict[str, Any]:
        """Fetch full detail for a single intel report by incident_id."""
        return self._get(_INTEL_DETAIL_ENDPOINT.format(incident_id=incident_id))
