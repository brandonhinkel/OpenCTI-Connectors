"""Alert importer for Cyware CSAP connector."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import stix2

from cyware_csap_services.client.alerts import AlertsAPI

from ..importer import BaseImporter
from .builder import AlertBundleBuilder

if TYPE_CHECKING:
    from cyware_csap_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class AlertImporter(BaseImporter):
    """Imports Cyware CSAP published alerts as OpenCTI Reports.

    State key: latest_alert_timestamp (int, UNIX epoch)
    On each run, fetches all PUBLISHED alerts with published_time >= start_ts,
    processes them page by page, and advances the timestamp to avoid re-fetching.
    """

    _NAME = "Alert"
    _LATEST_ALERT_TIMESTAMP = "latest_alert_timestamp"

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
    ) -> None:
        super().__init__(config, helper, author, tlp_marking)
        self.alerts_api = AlertsAPI(config, helper)

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        start_ts: int = state.get(
            self._LATEST_ALERT_TIMESTAMP,
            self.config.cyware.alert_start_timestamp,
        )
        self._info("Alert importer starting from timestamp {0}", start_ts)

        category_ids = list(self.config.cyware.alert_category_ids) or None
        tlp_filter = list(self.config.cyware.alert_tlp_filter) or None
        exclude_categories = {
            n.lower() for n in self.config.cyware.alert_exclude_category_names
        }
        page_size = self.config.cyware.alert_page_size

        latest_ts = start_ts
        total_imported = 0
        page = 1

        while True:
            try:
                response = self.alerts_api.list_alerts(
                    start_time=start_ts if start_ts else None,
                    page=page,
                    page_size=page_size,
                    category_ids=category_ids,
                    tlp_filter=tlp_filter,
                )
            except Exception as exc:
                self._error("Failed to list alerts on page {0}: {1}", page, exc)
                break

            alerts = response.get("data") or []
            total_count = response.get("count", 0)

            if not alerts:
                self._info("No alerts returned on page {0}.", page)
                break

            self._info(
                "Page {0}: processing {1} alerts ({2} total).",
                page, len(alerts), total_count,
            )

            for summary in alerts:
                short_id = summary.get("short_id")
                if not short_id:
                    continue

                try:
                    detail = self.alerts_api.get_alert_detail(short_id)
                except Exception as exc:
                    self._error("Failed to fetch detail for alert {0}: {1}", short_id, exc)
                    continue

                if exclude_categories:
                    cat_name = (
                        (detail.get("card_category") or {}).get("category_name") or ""
                    ).lower()
                    if cat_name in exclude_categories:
                        self._debug(
                            "Alert {0}: skipping excluded category '{1}'",
                            short_id, cat_name,
                        )
                        continue

                self._debug(
                    "Alert {0} detail keys: {1}; indicators keys: {2}",
                    short_id,
                    list(detail.keys()),
                    list((detail.get("indicators") or {}).keys()),
                )

                pdf_bytes = self.alerts_api.get_alert_pdf(short_id)
                if pdf_bytes:
                    self._debug("Alert {0}: PDF fetched ({1} bytes)", short_id, len(pdf_bytes))
                else:
                    self._debug("Alert {0}: no PDF available", short_id)

                try:
                    bundle = AlertBundleBuilder(
                        alert=detail,
                        author=self.author,
                        source_name=self._source_name(),
                        default_tlp=self.tlp_marking,
                        confidence=self._confidence_level(),
                        blacklist_score=self.config.cyware.indicator_blacklist_score,
                        whitelist_score=self.config.cyware.indicator_whitelist_score,
                        pdf_bytes=pdf_bytes,
                    ).build()
                    self._send_bundle(bundle)
                    self._debug(
                        "Alert {0} bundle sent: {1} STIX objects",
                        short_id, len(bundle.objects),
                    )
                    total_imported += 1
                except Exception as exc:
                    self._error(
                        "Failed to build or send bundle for alert {0}: {1}", short_id, exc
                    )
                    continue

                published_time = summary.get("published_time", 0)
                try:
                    if int(published_time) > latest_ts:
                        latest_ts = int(published_time)
                except (TypeError, ValueError):
                    pass

            if page * page_size >= total_count:
                break
            page += 1

        self._info(
            "Alert importer complete: {0} imported, latest_ts={1}.",
            total_imported, latest_ts,
        )

        # Advance by 1 second so the next run's start_time does not re-fetch
        # the alert at latest_ts. Only advance if we actually moved forward.
        next_ts = latest_ts + 1 if latest_ts > start_ts else latest_ts
        new_state = {self._LATEST_ALERT_TIMESTAMP: next_ts}
        self._set_state({**state, **new_state})
        return new_state
