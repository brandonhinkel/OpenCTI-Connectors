"""Intel importer for Cyware CSAP connector."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import stix2

from cyware_csap_services.client.intel import IntelAPI

from ..importer import BaseImporter
from .builder import IntelBundleBuilder

if TYPE_CHECKING:
    from cyware_csap_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper

# Maximum number of processed incident_ids to retain in state.
# Older entries are evicted when this limit is exceeded.
_MAX_STORED_IDS = 500


class IntelImporter(BaseImporter):
    """Imports Cyware CSAP member-submitted intel reports as OpenCTI Reports.

    The list_intel_reported endpoint has no time filter, so state is tracked via:
    - latest_intel_count: total record count on last successful run
    - processed_intel_ids: set of already-imported incident_ids (capped at 500)

    On each run, if the current count exceeds the stored count, the importer
    pages through from the newest records and stops as soon as it encounters a
    page of entirely known incident_ids.
    """

    _NAME = "Intel"
    _LATEST_INTEL_COUNT = "latest_intel_count"
    _PROCESSED_INTEL_IDS = "processed_intel_ids"

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
    ) -> None:
        super().__init__(config, helper, author, tlp_marking)
        self.intel_api = IntelAPI(config, helper)

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        stored_count: int = state.get(self._LATEST_INTEL_COUNT, 0)
        processed_ids: set[str] = set(state.get(self._PROCESSED_INTEL_IDS, []))
        page_size = self.config.cyware.intel_page_size

        self._info("Intel importer starting (stored_count={0}).", stored_count)

        try:
            first_page = self.intel_api.list_intel(page=1, page_size=1)
        except Exception as exc:
            self._error("Failed to fetch intel list: {0}", exc)
            return {}

        current_count: int = first_page.get("count", 0)

        if current_count <= stored_count and stored_count > 0:
            self._info("No new intel reports (count={0}).", current_count)
            return {self._LATEST_INTEL_COUNT: stored_count}

        self._info(
            "New intel reports detected (stored={0}, current={1}).",
            stored_count, current_count,
        )

        new_processed_ids = set(processed_ids)
        total_imported = 0
        page = 1

        while True:
            try:
                response = self.intel_api.list_intel(page=page, page_size=page_size)
            except Exception as exc:
                self._error("Failed to fetch intel page {0}: {1}", page, exc)
                break

            items = response.get("data") or []
            if not items:
                break

            all_known = True
            for item in items:
                incident_id = str(item.get("incident_id", "")).strip()
                if not incident_id or incident_id in processed_ids:
                    continue

                all_known = False

                try:
                    detail = self.intel_api.get_intel_detail(incident_id)
                except Exception as exc:
                    self._error(
                        "Failed to fetch intel detail {0}: {1}", incident_id, exc
                    )
                    continue

                try:
                    bundle = IntelBundleBuilder(
                        intel=detail,
                        author=self.author,
                        source_name=self._source_name(),
                        default_tlp=self.tlp_marking,
                        confidence=self._confidence_level(),
                        blacklist_score=self.config.cyware.indicator_blacklist_score,
                        whitelist_score=self.config.cyware.indicator_whitelist_score,
                    ).build()
                    self._send_bundle(bundle)
                    new_processed_ids.add(incident_id)
                    total_imported += 1
                except Exception as exc:
                    self._error(
                        "Failed to build or send intel bundle {0}: {1}", incident_id, exc
                    )
                    continue

            # Stop when an entire page consists of already-known IDs
            if all_known:
                self._info("Page {0} fully known, stopping.", page)
                break

            total = response.get("count", 0)
            if page * page_size >= total:
                break
            page += 1

        self._info("Intel importer complete: {0} reports imported.", total_imported)

        # Evict oldest entries to keep state size bounded
        if len(new_processed_ids) > _MAX_STORED_IDS:
            new_processed_ids = set(list(new_processed_ids)[-_MAX_STORED_IDS:])

        new_state = {
            self._LATEST_INTEL_COUNT: current_count,
            self._PROCESSED_INTEL_IDS: list(new_processed_ids),
        }
        self._set_state({**state, **new_state})
        return new_state
