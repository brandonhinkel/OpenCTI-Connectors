"""STIX 2.1 bundle builder for Cyware CSAP member-submitted intel reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import stix2
from pycti import Identity as PyCTIIdentity
from pycti import Report as PyCTIReport

from cyware_csap_services.utils.constants import get_tlp_marking, html_to_markdown
from cyware_csap_services.utils.observables import create_ioc_objects


class IntelBundleBuilder:
    """Builds a STIX 2.1 bundle from a Cyware CSAP intel report detail object.

    Intel reports are member-submitted and have a simpler structure than
    analyst-published alerts. Fields are handled defensively since the exact
    detail schema was not confirmed during pre-build probing.
    """

    def __init__(
        self,
        intel: dict[str, Any],
        author: stix2.Identity,
        source_name: str,
        default_tlp: stix2.MarkingDefinition,
        confidence: int,
        blacklist_score: int,
        whitelist_score: int,
    ) -> None:
        self.intel = intel
        self.author = author
        self.source_name = source_name
        self.default_tlp = default_tlp
        self.confidence = confidence
        self.blacklist_score = blacklist_score
        self.whitelist_score = whitelist_score

    _PLACEHOLDER_NAME = "CYWARE EMPTY REPORT"

    def build(self) -> stix2.Bundle:
        """Build and return the STIX bundle for this intel report."""
        tlp = self._resolve_tlp()
        now = datetime.now(timezone.utc)

        ioc_objects = self._build_ioc_objects(tlp, now)

        if ioc_objects:
            object_refs = [str(o.id) for o in ioc_objects]
            extra_objects: list = []
        else:
            placeholder = self._create_placeholder()
            object_refs = [str(placeholder.id)]
            extra_objects = [placeholder]

        report = self._build_report(tlp, now, object_refs)

        return stix2.Bundle(
            objects=[self.author] + extra_objects + [report] + ioc_objects,
            allow_custom=True,
        )

    def _create_placeholder(self) -> stix2.Identity:
        """Placeholder Identity used when an intel report has no IOC objects."""
        return stix2.Identity(
            id=PyCTIIdentity.generate_id(self._PLACEHOLDER_NAME, "organization"),
            name=self._PLACEHOLDER_NAME,
            identity_class="organization",
        )

    def _resolve_tlp(self) -> stix2.MarkingDefinition:
        return get_tlp_marking(self.intel.get("tlp"), self.default_tlp)

    def _build_labels(self) -> list[str]:
        labels: list[str] = []
        category = self.intel.get("category") or {}
        if cat_name := category.get("category_name"):
            labels.append(f"category:{cat_name.strip()}")
        return labels

    def _build_external_refs(self) -> list[dict]:
        incident_id = str(self.intel.get("incident_id", ""))
        return [{"source_name": self.source_name, "external_id": incident_id}]

    def _build_ioc_objects(
        self,
        tlp: stix2.MarkingDefinition,
        valid_from: datetime,
    ) -> list:
        """Extract IOCs from intel detail if the indicators field is present."""
        indicators_data = self.intel.get("indicators") or {}
        objects: list = []

        for ioc_type, bucket in indicators_data.items():
            if isinstance(bucket, dict):
                for value in bucket.get("blacklisted") or []:
                    objects.extend(
                        create_ioc_objects(
                            ioc_type=ioc_type,
                            value=str(value),
                            is_blacklisted=True,
                            score=self.blacklist_score,
                            valid_from=valid_from,
                            author=self.author,
                            tlp_marking=tlp,
                        )
                    )
                for value in bucket.get("whitelisted") or []:
                    objects.extend(
                        create_ioc_objects(
                            ioc_type=ioc_type,
                            value=str(value),
                            is_blacklisted=False,
                            score=self.whitelist_score,
                            valid_from=valid_from,
                            author=self.author,
                            tlp_marking=tlp,
                        )
                    )
            elif isinstance(bucket, list):
                for value in bucket:
                    objects.extend(
                        create_ioc_objects(
                            ioc_type=ioc_type,
                            value=str(value),
                            is_blacklisted=True,
                            score=self.blacklist_score,
                            valid_from=valid_from,
                            author=self.author,
                            tlp_marking=tlp,
                        )
                    )

        return objects

    def _build_report(
        self,
        tlp: stix2.MarkingDefinition,
        published_dt: datetime,
        object_refs: list[str],
    ) -> stix2.Report:
        title = (
            self.intel.get("title")
            or str(self.intel.get("incident_id", "Intel Report"))
        ).strip()
        description = html_to_markdown(self.intel.get("description") or "") or None
        labels = self._build_labels() or None
        external_refs = self._build_external_refs()

        return stix2.Report(
            id=PyCTIReport.generate_id(title, published_dt.isoformat()),
            name=title,
            description=description,
            published=published_dt,
            report_types=["threat-report"],
            created_by_ref=self.author.id,
            object_marking_refs=[tlp],
            labels=labels,
            external_references=external_refs,
            object_refs=object_refs,
            custom_properties={
                "x_opencti_report_status": 0,
                "x_opencti_confidence_level": self.confidence,
            },
            allow_custom=True,
        )
