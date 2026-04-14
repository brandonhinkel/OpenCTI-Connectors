import json
import ssl
import sys
import time
import urllib
from datetime import datetime, timezone
from typing import Optional

from pycti import OpenCTIConnectorHelper
from src import ConfigLoader

from .constants import F3_ATTACK_KILL_CHAIN_PHASES


def time_from_unixtime(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def get_unixtime_now():
    return int(time.time())


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


def filter_stix_revoked(revoked_ids, stix):
    # Pure revoke
    if stix["id"] in revoked_ids:
        return False
    # Side of relationship revoked
    if stix["type"] == "relationship" and (
        stix["source_ref"] in revoked_ids or stix["target_ref"] in revoked_ids
    ):
        return False
    # Side of sighting revoked
    if stix["type"] == "sighting" and (
        stix["sighting_of_ref"] in revoked_ids
        or any(ref in revoked_ids for ref in stix["where_sighted_refs"])
    ):
        return False
    return True


class MitreF3:
    """MITRE Fight Fraud Framework (F3) connector."""

    def __init__(self):
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        self.f3_interval = self.config.f3.interval
        self.f3_file_url = self.config.f3.file_url
        self.interval = days_to_seconds(self.f3_interval)

    def retrieve_data(self, url: str) -> Optional[dict]:
        """
        Retrieve and pre-process the F3 STIX bundle from the given URL.

        Parameters
        ----------
        url : str
            URL to fetch the STIX bundle from.

        Returns
        -------
        dict or None
            The processed STIX bundle, or None on failure.
        """
        try:
            serialized_bundle = (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            stix_bundle = json.loads(serialized_bundle)
            stix_objects = stix_bundle["objects"]

            # Filter revoked objects
            revoked_objects = list(
                filter(
                    lambda stix: stix.get("revoked", False) is True,
                    stix_objects,
                )
            )
            revoked_ids = list(map(lambda stix: stix["id"], revoked_objects))
            stix_bundle["objects"] = list(
                filter(
                    lambda stix: filter_stix_revoked(revoked_ids, stix), stix_objects
                )
            )

            # Enrich kill chain phases with x_opencti_order and versioned phases
            self.enrich_kill_chain_phases(stix_bundle)
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
            self.helper.metric.inc("client_error_count")
        return None

    @staticmethod
    def get_collection_major_version(stix_bundle: dict) -> Optional[str]:
        """
        Extract the major version from the x-mitre-collection object in the bundle.

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to search.

        Returns
        -------
        Optional[str]
            The major version (e.g., "1" from "1.0") or None if not found.
        """
        for obj in stix_bundle["objects"]:
            if obj.get("type") == "x-mitre-collection":
                version_str = obj.get("x_mitre_version", "")
                if version_str:
                    return version_str.split(".")[0]
        return None

    @staticmethod
    def _build_kill_chain_order_mapping() -> dict:
        """
        Build a mapping from (kill_chain_name, phase_name) to x_opencti_order.

        Returns
        -------
        dict
            A dictionary mapping (kill_chain_name, phase_name) tuples to order values.
        """
        mapping = {}
        for phase in F3_ATTACK_KILL_CHAIN_PHASES:
            mapping[("mitre-f3", phase["name"])] = phase["order"]
        return mapping

    def enrich_kill_chain_phases(self, stix_bundle: dict):
        """
        Enrich kill chain phases in attack patterns with x_opencti_order and versioned phases.

        Adds x_opencti_order to each kill chain phase and, when an x-mitre-collection
        version is present, appends a versioned phase (e.g., "mitre-f3-v1").

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to process in-place.
        """
        order_mapping = self._build_kill_chain_order_mapping()
        collection_version = self.get_collection_major_version(stix_bundle)

        if collection_version:
            self.helper.log_info(
                f"Found F3 collection major version: {collection_version}"
            )
        else:
            self.helper.log_warning(
                "Could not find x-mitre-collection version in bundle, skipping versioned kill chain phases"
            )

        for obj in stix_bundle["objects"]:
            if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj:
                enriched_phases = []
                for phase in obj["kill_chain_phases"]:
                    kill_chain_name = phase.get("kill_chain_name", "")
                    phase_name = phase.get("phase_name", "")

                    order = order_mapping.get((kill_chain_name, phase_name))

                    enriched_phase = {
                        "kill_chain_name": kill_chain_name,
                        "phase_name": phase_name,
                    }
                    if order is not None:
                        enriched_phase["x_opencti_order"] = order

                    enriched_phases.append(enriched_phase)

                    # Add versioned kill chain phase
                    if collection_version and kill_chain_name == "mitre-f3":
                        versioned_phase = {
                            "kill_chain_name": f"mitre-f3-v{collection_version}",
                            "phase_name": phase_name,
                        }
                        if order is not None:
                            versioned_phase["x_opencti_order"] = order
                        enriched_phases.append(versioned_phase)

                obj["kill_chain_phases"] = enriched_phases

    def process_data(self):
        unixtime_now = get_unixtime_now()
        time_now = time_from_unixtime(unixtime_now)

        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", None) if current_state else None
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")

        if last_run and self.interval > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return

        self.helper.log_info(f"Connector will run now {time_now}.")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        friendly_name = f"MITRE F3 run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self.helper.log_info("Fetching MITRE Fight Fraud Framework (F3) dataset...")
        data = self.retrieve_data(self.f3_file_url)

        if data:
            self.helper.send_stix2_bundle(
                json.dumps(data),
                entities_types=self.helper.connect_scope,
                work_id=work_id,
                update=True,
            )
            self.helper.metric.inc("record_send", len(data["objects"]))

        message = f"Connector successfully run, storing last_run as {time_now}"
        self.helper.log_info(message)
        self.helper.set_state({"last_run": unixtime_now})
        self.helper.api.work.to_processed(work_id, message)

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)

        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                self.helper.metric.state("idle")
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = MitreF3()
        connector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
