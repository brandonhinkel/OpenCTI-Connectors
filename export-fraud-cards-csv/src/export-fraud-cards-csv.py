import csv
import io
import json
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from bin_lookup import BinLookup
from card_parser import parse_cards

CSV_HEADERS = [
    "card_number",
    "expiration_month",
    "expiration_year",
    "cvv",
    "cardholder_name",
    "bin",
    "bin_brand",
    "bin_type",
    "bin_category",
    "bin_issuer",
    "bin_issuer_phone",
    "bin_issuer_url",
    "bin_country_name",
    "bin_iso_code2",
    "bin_iso_code3",
    "source_id",
    "source_value",
]

# Default BIN DB path relative to this file (override via env / config)
_DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "data", "bin_lookup.db"
)


class ExportFraudCardsCsv:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        bin_db_path = get_config_variable(
            "EXPORT_FRAUD_CARDS_BIN_DB_PATH",
            ["export-fraud-cards-csv", "bin_db_path"],
            config,
            False,
            _DEFAULT_DB_PATH,
        )
        self.bin_lookup = BinLookup(bin_db_path)
        if self.bin_lookup.available:
            self.helper.connector_logger.info(
                "BIN lookup database loaded", {"path": bin_db_path}
            )
        else:
            self.helper.connector_logger.warning(
                "BIN lookup database not found — BIN enrichment disabled",
                {"path": bin_db_path},
            )

    # ── CSV construction ──────────────────────────────────────────────────────

    @staticmethod
    def _text_value(entity: dict) -> str:
        """Return the text content of a Text observable."""
        return entity.get("value") or entity.get("observable_value") or ""

    def _build_csv(self, text_observables: list[dict]) -> tuple[str, int]:
        """Parse card data from Text observables and return (csv_string, row_count)."""
        output = io.StringIO()
        writer = csv.writer(output, delimiter=",", quotechar='"', quoting=csv.QUOTE_ALL)
        writer.writerow(CSV_HEADERS)

        row_count = 0
        for entity in text_observables:
            raw_text = self._text_value(entity)
            if not raw_text:
                continue

            cards = parse_cards(raw_text)
            for card in cards:
                bin_info = self.bin_lookup.lookup(card.card_number)
                writer.writerow([
                    card.card_number,
                    card.expiration_month,
                    card.expiration_year,
                    card.cvv,
                    card.cardholder_name,
                    card.card_number[:6],
                    bin_info.get("brand", ""),
                    bin_info.get("type", ""),
                    bin_info.get("category", ""),
                    bin_info.get("issuer", ""),
                    bin_info.get("issuer_phone", ""),
                    bin_info.get("issuer_url", ""),
                    bin_info.get("country_name", ""),
                    bin_info.get("iso_code2", ""),
                    bin_info.get("iso_code3", ""),
                    entity.get("id", ""),
                    raw_text,
                ])
                row_count += 1

        return output.getvalue(), row_count

    # ── Upload helpers ────────────────────────────────────────────────────────

    def _push_list_export(self, data: dict, csv_data: str, list_filters: str):
        entity_type = data["entity_type"]
        entity_id = data.get("entity_id")
        file_name = data["file_name"]
        file_markings = data["file_markings"]

        if entity_type == "Stix-Cyber-Observable":
            self.helper.api.stix_cyber_observable.push_list_export(
                entity_id, entity_type, file_name, file_markings, csv_data, list_filters
            )
        elif entity_type == "Stix-Core-Object":
            self.helper.api.stix_core_object.push_list_export(
                entity_id, entity_type, file_name, file_markings, csv_data, list_filters
            )
        else:
            self.helper.api.stix_domain_object.push_list_export(
                entity_id, entity_type, file_name, file_markings, csv_data, list_filters
            )

        self.helper.connector_logger.info(
            "Export done",
            {
                "entity_type": entity_type,
                "export_type": data["export_type"],
                "file_name": file_name,
            },
        )

    # ── Message handler ───────────────────────────────────────────────────────

    def _process_message(self, data: dict) -> str:
        file_name = data["file_name"]
        export_scope = data["export_scope"]   # single | selection | query
        export_type = data["export_type"]
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        main_filter = data.get("main_filter")
        access_filter = data.get("access_filter")

        # ── Container export ──────────────────────────────────────────────────
        # Analyst exports from a Report / Grouping / Investigation.
        # We fetch all objects in the container and keep only Text observables.
        if export_scope == "single":
            self.helper.connector_logger.info(
                "Exporting container",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

            do_read = self.helper.api.stix2.get_reader(entity_type)
            entity_data = do_read(id=entity_id)
            if entity_data is None:
                raise ValueError(
                    "Unable to read/access the entity. Ensure the connector has "
                    "admin permission so it can impersonate the requesting user."
                )

            text_observables: list[dict] = []
            object_ids = entity_data.get("objectsIds")
            if object_ids:
                filter_groups = [
                    {
                        "mode": "or",
                        "filters": [{"key": "ids", "values": object_ids}],
                        "filterGroups": [],
                    }
                ]
                if access_filter:
                    filter_groups.append(access_filter)

                all_objects = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                    filters={"mode": "and", "filterGroups": filter_groups, "filters": []},
                    getAll=True,
                )
                text_observables = [
                    e for e in all_objects if e.get("entity_type") == "Text"
                ]

            csv_data, row_count = self._build_csv(text_observables)
            self.helper.connector_logger.info(
                "Uploading export",
                {
                    "entity_id": entity_id,
                    "file_name": file_name,
                    "card_records": row_count,
                    "source_observables": len(text_observables),
                },
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id=entity_id,
                file_name=file_name,
                data=csv_data,
                file_markings=file_markings,
            )
            self.helper.connector_logger.info(
                "Export done",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )

        # ── Manual selection export ───────────────────────────────────────────
        # Analyst manually selects observables from the list view.
        if export_scope == "selection":
            all_objects = self.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list(
                filters=main_filter, getAll=True
            )
            text_observables = [
                e for e in all_objects if e.get("entity_type") == "Text"
            ]
            csv_data, row_count = self._build_csv(text_observables)
            self.helper.connector_logger.info(
                "Selection export",
                {
                    "card_records": row_count,
                    "source_observables": len(text_observables),
                },
            )
            self._push_list_export(data, csv_data, "selected_ids")

        # ── Query export ──────────────────────────────────────────────────────
        # Analyst exports from the Text observables list view with filters applied.
        if export_scope == "query":
            list_params = data["list_params"]
            list_params_filters = list_params.get("filters")

            filter_groups = []
            if list_params_filters is not None:
                filter_groups.append(list_params_filters)
            if access_filter is not None:
                filter_groups.append(access_filter)

            all_objects = self.helper.api_impersonate.stix2.export_entities_list(
                entity_type=entity_type,
                search=list_params.get("search"),
                filters={"mode": "and", "filterGroups": filter_groups, "filters": []},
                orderBy=list_params.get("orderBy"),
                orderMode=list_params.get("orderMode"),
                getAll=True,
            )
            text_observables = [
                e for e in all_objects if e.get("entity_type") == "Text"
            ]
            csv_data, row_count = self._build_csv(text_observables)
            self.helper.connector_logger.info(
                "Query export",
                {
                    "card_records": row_count,
                    "source_observables": len(text_observables),
                },
            )
            self._push_list_export(data, csv_data, json.dumps(list_params))

        return "Export done"

    # ── Entry point ───────────────────────────────────────────────────────────

    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = ExportFraudCardsCsv()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
