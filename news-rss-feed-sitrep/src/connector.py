"""
connector.py — OpenCTI RSS Threat Intelligence SITREP Connector (v2).

Run loop entry point.  Loads config, initialises the OpenCTI helper, pre-loads
ML models at startup, then runs the pipeline on an interval-based schedule and
writes the daily SITREP Report to OpenCTI.

Environment variable overrides (all optional; config.yml values are the fallback):
  OPENCTI_URL             OpenCTI platform URL
  OPENCTI_TOKEN           OpenCTI API token
  CONNECTOR_ID            Unique connector instance UUID
  CONNECTOR_NAME          Display name in OpenCTI
  CONNECTOR_LOG_LEVEL     Logging verbosity (debug/info/warning/error)
  CONNECTOR_DURATION_PERIOD  Run interval as ISO 8601 duration (e.g. PT2H)
  RSS_CONNECTOR_CONFIDENCE   Default confidence level (integer, default 50)
  RSS_CONNECTOR_TLP          TLP marking (WHITE/GREEN/AMBER/RED, default WHITE)
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("connector")

_DEFAULT_CONFIG_PATH = "/opt/opencti-connector-rss/config.yml"


def _load_config(path: str) -> dict:
    """Load and return the YAML config, raising clearly if the file is missing."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Set CONFIG_PATH to override the default location."
        )
    with p.open() as f:
        return yaml.safe_load(f) or {}


class RSSConnector:
    """OpenCTI RSS SITREP Connector v2."""

    def __init__(self, config: dict):
        from pycti import OpenCTIConnectorHelper

        self.config = config
        self.pipeline_config: dict = config.get("rss_connector", {})

        # Allow individual env var overrides for confidence/TLP without needing
        # to modify the mounted config.yml.
        if "RSS_CONNECTOR_CONFIDENCE" in os.environ:
            self.pipeline_config["confidence"] = int(os.environ["RSS_CONNECTOR_CONFIDENCE"])
        if "RSS_CONNECTOR_TLP" in os.environ:
            self.pipeline_config["tlp"] = os.environ["RSS_CONNECTOR_TLP"].upper()

        self.helper = OpenCTIConnectorHelper(config)
        self._preload_models()
        self._alias_table = self._build_alias_table()

    def _build_alias_table(self) -> dict:
        """Fetch the actor alias table from OpenCTI IntrusionSets at startup."""
        from opencti_writer import build_actor_alias_table
        table = build_actor_alias_table(self.helper)
        logger.info(f"[Connector] Actor alias table: {len(table)} entries")
        return table

    def _preload_models(self) -> None:
        """
        Load all ML models at startup and hold them in memory.

        Models are expensive to load (~30–60s on CPU).  Pre-loading here means
        each pipeline run uses already-warm models rather than re-loading.
        """
        from pipeline import get_classifier, get_embedder, get_gliner, get_summarizer

        logger.info("Pre-loading ML models...")
        get_embedder(self.pipeline_config)
        get_gliner(self.pipeline_config)
        get_classifier(self.pipeline_config)
        if self.pipeline_config.get("summarization_enabled", False):
            get_summarizer(self.pipeline_config)
        logger.info("ML models loaded and ready.")

    # ------------------------------------------------------------------
    # Run callback
    # ------------------------------------------------------------------

    def process_message(self) -> None:
        """
        Entry point called by the OpenCTI scheduler on each run interval.

        Stages:
          1. Initiate a work item (visible in OpenCTI UI)
          2. Run the NLP pipeline
          3. Generate SITREP HTML content
          4. Write the STIX bundle to OpenCTI
          5. Save connector state
          6. Mark the work item as completed
        """
        from opencti_writer import OpenCTIWriter
        from pipeline import run_pipeline
        from sitrep import generate_executive_summary, generate_sitrep_html
        from state import ConnectorState

        self.helper.log_info("[Connector] Starting RSS SITREP run...")

        work_id: Optional[str] = None
        try:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "RSS SITREP — pipeline run",
            )
        except Exception as exc:
            logger.warning(f"Could not initiate work item: {exc}")

        try:
            # --- Stage 1: load connector state ---
            connector_state = ConnectorState(self.helper)
            self.helper.log_info(
                f"[Connector] State loaded: {len(connector_state)} URLs tracked"
            )

            # --- Stage 2: run the NLP pipeline ---
            self.helper.log_info("[Connector] Running pipeline...")
            result = run_pipeline(
                self.pipeline_config,
                known_urls=connector_state.ingested_urls,
                alias_table=self._alias_table,
            )
            self.helper.log_info(
                f"[Connector] Pipeline complete: "
                f"{result.stats.get('clusters', 0)} clusters from "
                f"{result.stats.get('articles_relevant', 0)} articles "
                f"in {result.stats.get('elapsed_seconds', 0):.1f}s"
            )

            if not result.clusters:
                self.helper.log_warning(
                    "[Connector] Pipeline produced 0 clusters — check feed config and logs."
                )

            # --- Stage 3: platform anchor lookup + SITREP content ---
            # OpenCTIWriter is created first so anchor_candidates can use the
            # EntityResolver (with its within-run cache) before HTML generation.
            writer = OpenCTIWriter(self.helper, self.pipeline_config)
            self.helper.log_info("[Connector] Running platform anchor lookup...")
            writer.anchor_candidates(result)

            self.helper.log_info("[Connector] Generating SITREP narrative...")
            sitrep_html = generate_sitrep_html(result)
            exec_summary = generate_executive_summary(result)

            # --- Stage 4: write to OpenCTI ---
            self.helper.log_info("[Connector] Writing STIX bundle to OpenCTI...")
            writer.write_sitrep(
                result=result,
                sitrep_html=sitrep_html,
                exec_summary=exec_summary,
                work_id=work_id,
                state=connector_state,
            )

            # --- Stage 5: persist state ---
            connector_state.save()
            self.helper.log_info("[Connector] State saved.")

            # --- Mark work complete ---
            if work_id:
                try:
                    self.helper.api.work.to_processed(
                        work_id,
                        f"SITREP written: {result.stats.get('clusters', 0)} clusters, "
                        f"{result.stats.get('articles_relevant', 0)} articles",
                    )
                except Exception as exc:
                    logger.warning(f"Could not mark work as processed: {exc}")

            self.helper.log_info("[Connector] Run complete.")

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("[Connector] Connector stopping.")
            sys.exit(0)

        except Exception as exc:
            error_msg = f"Run failed: {exc}\n{traceback.format_exc()}"
            self.helper.log_error(f"[Connector] {error_msg}")

            if work_id:
                try:
                    self.helper.api.work.to_processed(
                        work_id,
                        f"Run failed: {exc}",
                    )
                except Exception:
                    pass
            raise

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the connector's scheduling loop (blocks indefinitely)."""
        # schedule_iso uses the connector.duration_period field from config
        # (or CONNECTOR_DURATION_PERIOD env var) to determine the run interval.
        try:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.config.get("connector", {}).get(
                    "duration_period", "PT2H"
                ),
            )
        except AttributeError:
            # Older pycti versions may not have schedule_iso; fall back to listen
            logger.warning(
                "helper.schedule_iso not available; falling back to helper.listen"
            )
            self.helper.listen(message_callback=self.process_message)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    config_path = os.environ.get("CONFIG_PATH", _DEFAULT_CONFIG_PATH)
    try:
        config = _load_config(config_path)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        connector = RSSConnector(config)
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
