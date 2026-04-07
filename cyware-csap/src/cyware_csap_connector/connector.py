"""Cyware CSAP OpenCTI connector — core orchestration."""

from __future__ import annotations

import sys
import time
import traceback
from typing import TYPE_CHECKING, Any, cast

import stix2
from pycti import Identity as PyCTIIdentity

from cyware_csap_services.utils.constants import CONFIG_TLP_MAP

from .alert.importer import AlertImporter
from .importer import BaseImporter
from .intel.importer import IntelImporter

if TYPE_CHECKING:
    from cyware_csap_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class CywareCSAP:
    """Main Cyware CSAP connector.

    Orchestrates the alert and intel importers on a schedule driven by
    CONNECTOR_DURATION_PERIOD. Each importer run is tracked as a separate
    OpenCTI work item so progress is visible in the platform UI.
    """

    _SCOPE_ALERT = "alert"
    _SCOPE_INTEL = "intel"
    _STATE_LAST_RUN = "last_run"

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
    ) -> None:
        self.config = config
        self.helper = helper

        tlp_marking = CONFIG_TLP_MAP.get(config.cyware.tlp, stix2.TLP_AMBER)
        author = self._create_author()
        scopes = set(config.cyware.scopes)

        importers: list[BaseImporter] = []

        if self._SCOPE_ALERT in scopes:
            importers.append(AlertImporter(config, helper, author, tlp_marking))

        if self._SCOPE_INTEL in scopes:
            importers.append(IntelImporter(config, helper, author, tlp_marking))

        if not importers:
            helper.log_warning(
                "[Connector] No valid scopes configured. "
                "Check CYWARE_SCOPES (available: alert, intel)."
            )

        self.importers = importers

    # ------------------------------------------------------------------
    # Connector lifecycle
    # ------------------------------------------------------------------

    def process_message(self) -> None:
        """Entry point called by the OpenCTI scheduler on each run."""
        self.helper.log_info("[Connector] Cyware CSAP run starting...")

        if not self.importers:
            self.helper.log_error("[Connector] No importers configured — nothing to do.")
            return

        try:
            state: dict[str, Any] = self.helper.get_state() or {}
            self.helper.log_info(f"[Connector] Loaded state: {state}")

            for importer in self.importers:
                importer_name = importer.name or importer.__class__.__name__
                work_id = self._initiate_work(importer_name)

                try:
                    importer_state = importer.start(work_id, state)
                    state.update(importer_state)
                    self.helper.set_state(state)
                    self.helper.api.work.to_processed(
                        work_id,
                        f"{self.helper.connect_name}/{importer_name} completed successfully",
                    )
                except Exception as exc:
                    self.helper.log_error(
                        f"[Connector] Importer '{importer_name}' raised an error: {exc}\n"
                        f"{traceback.format_exc()}"
                    )
                    try:
                        self.helper.api.work.to_processed(
                            work_id,
                            f"{importer_name} failed: {exc}",
                        )
                    except Exception:
                        pass

            state[self._STATE_LAST_RUN] = int(time.time())
            self.helper.set_state(state)
            self.helper.log_info("[Connector] Cyware CSAP run complete.")

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("[Connector] Cyware CSAP connector stopping.")
            sys.exit(0)

        except Exception as exc:
            self.helper.log_error(
                f"[Connector] Unexpected error during run: {exc}\n"
                f"{traceback.format_exc()}"
            )

    def run(self) -> None:
        """Start the connector's scheduling loop (blocks indefinitely)."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_author() -> stix2.Identity:
        """Create the Cyware STIX Identity with a deterministic ID."""
        return stix2.Identity(
            id=PyCTIIdentity.generate_id("Cyware", "organization"),
            name="Cyware",
            identity_class="organization",
        )

    def _initiate_work(self, importer_name: str) -> str:
        timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        friendly_name = (
            f"{self.helper.connect_name}/{importer_name} @ {timestamp_str}"
        )
        connect_id = cast(str, self.helper.connect_id)
        work_id = cast(
            str,
            self.helper.api.work.initiate_work(connect_id, friendly_name),
        )
        self.helper.log_info(
            f"[Connector] Work '{work_id}' initiated for '{importer_name}'"
        )
        return work_id
