"""STIX 2.1 bundle builder for Cyware CSAP alert (card) objects."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import stix2
from pycti import Identity as PyCTIIdentity
from pycti import Report as PyCTIReport

from cyware_csap_services.utils.constants import get_tlp_marking, strip_html
from cyware_csap_services.utils.observables import create_ioc_objects


class AlertBundleBuilder:
    """Builds a STIX 2.1 bundle from a Cyware CSAP alert detail object.

    Bundle contents:
    - stix2.Identity (author, passed in — always included)
    - stix2.Report (the alert itself)
    - For each IOC in alert.indicators:
        - Blacklisted: Observable + Indicator + Relationship(based-on)
        - Whitelisted: Observable only
    """

    def __init__(
        self,
        alert: dict[str, Any],
        author: stix2.Identity,
        source_name: str,
        default_tlp: stix2.MarkingDefinition,
        confidence: int,
        blacklist_score: int,
        whitelist_score: int,
    ) -> None:
        self.alert = alert
        self.author = author
        self.source_name = source_name
        self.default_tlp = default_tlp
        self.confidence = confidence
        self.blacklist_score = blacklist_score
        self.whitelist_score = whitelist_score

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def build(self) -> stix2.Bundle:
        """Build and return the complete STIX bundle for this alert."""
        tlp = self._resolve_tlp()
        published_dt = self._published_datetime()

        ioc_objects = self._build_ioc_objects(tlp, published_dt)

        # Compute object_refs before building the Report.
        # The author is NEVER included in object_refs — it is only set via
        # created_by_ref so it does not appear as an entity in the report.
        # When no IOCs are present, use a named placeholder Identity so the
        # Report's required object_refs constraint is satisfied without
        # surfacing the author as a report entity.
        if ioc_objects:
            object_refs = [str(o.id) for o in ioc_objects]
            extra_objects: list = []
        else:
            placeholder = self._create_placeholder()
            object_refs = [str(placeholder.id)]
            extra_objects = [placeholder]

        report = self._build_report(tlp, published_dt, object_refs)

        return stix2.Bundle(
            objects=[self.author] + extra_objects + [report] + ioc_objects,
            allow_custom=True,
        )

    def _create_placeholder(self) -> stix2.Identity:
        """Named placeholder Identity used when an alert has no IOC objects.

        Satisfies the STIX 2.1 requirement that Report.object_refs is non-empty
        without putting the connector author into the report's entity list.
        The deterministic ID means all empty-IOC reports share the same
        placeholder entity in OpenCTI.
        """
        return stix2.Identity(
            id=PyCTIIdentity.generate_id("Cyware CSAP (no indicators)", "organization"),
            name="Cyware CSAP (no indicators)",
            identity_class="organization",
        )

    # ------------------------------------------------------------------
    # TLP
    # ------------------------------------------------------------------

    def _resolve_tlp(self) -> stix2.MarkingDefinition:
        """Use the alert's own TLP when present, else the connector default."""
        return get_tlp_marking(self.alert.get("tlp"), self.default_tlp)

    # ------------------------------------------------------------------
    # Datetime
    # ------------------------------------------------------------------

    def _published_datetime(self) -> datetime:
        ts = self.alert.get("published_time")
        if ts:
            try:
                return datetime.fromtimestamp(int(ts), tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                pass
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Labels
    # ------------------------------------------------------------------

    def _build_labels(self) -> list[str]:
        labels: list[str] = []

        card_category = self.alert.get("card_category") or {}
        if cat_name := card_category.get("category_name"):
            labels.append(f"category:{cat_name.strip()}")

        for tag in self.alert.get("card_tag") or []:
            if tag_name := tag.get("tag_name"):
                labels.append(tag_name.strip())

        severity = self.alert.get("severity") or {}
        if sev_name := severity.get("severity_name"):
            labels.append(f"severity:{sev_name.strip()}")

        confidence_obj = self.alert.get("confidence") or {}
        if conf_name := confidence_obj.get("confidence_name"):
            labels.append(f"confidence:{conf_name.strip()}")

        credibility = self.alert.get("credibility") or {}
        if cred_name := credibility.get("credibility_name"):
            labels.append(f"credibility:{cred_name.strip()}")

        for dm in self.alert.get("detectionmethod") or []:
            if dm_name := dm.get("detectionmethod_name"):
                labels.append(f"detection:{dm_name.strip()}")

        return labels

    # ------------------------------------------------------------------
    # External references
    # ------------------------------------------------------------------

    def _build_external_refs(self) -> list[dict]:
        refs: list[dict] = [
            {
                "source_name": self.source_name,
                "external_id": self.alert.get("short_id", ""),
            }
        ]

        for item in self.alert.get("source_urls") or []:
            if isinstance(item, str) and item.strip():
                refs.append({"source_name": "Reference", "url": item.strip()})
            elif isinstance(item, dict):
                url = (item.get("url") or "").strip()
                name = (item.get("source_name") or "Reference").strip()
                if url:
                    refs.append({"source_name": name, "url": url})

        return refs

    # ------------------------------------------------------------------
    # IOC objects
    # ------------------------------------------------------------------

    def _build_ioc_objects(
        self,
        tlp: stix2.MarkingDefinition,
        published_dt: datetime,
    ) -> list:
        """Extract all IOCs from alert.indicators and create STIX objects."""
        indicators_data = self.alert.get("indicators") or {}
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
                            valid_from=published_dt,
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
                            valid_from=published_dt,
                            author=self.author,
                            tlp_marking=tlp,
                        )
                    )
            elif isinstance(bucket, list):
                # Flat list — treat as blacklisted by convention
                for value in bucket:
                    objects.extend(
                        create_ioc_objects(
                            ioc_type=ioc_type,
                            value=str(value),
                            is_blacklisted=True,
                            score=self.blacklist_score,
                            valid_from=published_dt,
                            author=self.author,
                            tlp_marking=tlp,
                        )
                    )

        return objects

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _build_report(
        self,
        tlp: stix2.MarkingDefinition,
        published_dt: datetime,
        object_refs: list[str],
    ) -> stix2.Report:
        title = (
            self.alert.get("title") or self.alert.get("short_id") or "Untitled"
        ).strip()
        description = strip_html(self.alert.get("content") or "") or None
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
