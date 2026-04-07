"""Factory for creating STIX 2.1 observables and indicators from Cyware IOCs.

Design constraint: indicators are ONLY created for IOCs that are embedded in
an alert or intel report bundle. There is no standalone indicator import.
OpenCTI is used for report ingestion and automatically forwards report-linked
indicators to MISP.

Blacklisted IOCs → Observable + Indicator + based-on Relationship
Whitelisted IOCs → Observable only (context, not treated as a threat)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import stix2
from pycti import Indicator as PyCTIIndicator

from .constants import IOC_TYPE_TO_OPENCTI_TYPE


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _stix_escape(value: str) -> str:
    """Escape backslashes and single quotes for use in STIX pattern strings."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _make_observable(
    ioc_type: str,
    value: str,
    author: stix2.Identity,
    tlp_marking: stix2.MarkingDefinition,
    score: int,
) -> Any | None:
    """Create the appropriate STIX SCO for the given IOC type and value.

    Returns None for unknown types or invalid values.
    """
    common: dict[str, Any] = dict(
        object_marking_refs=[tlp_marking],
        custom_properties={
            "created_by_ref": str(author.id),
            "x_opencti_score": score,
        },
        allow_custom=True,
    )
    try:
        if ioc_type == "domain":
            return stix2.DomainName(value=value, **common)
        if ioc_type == "ip":
            return stix2.IPv4Address(value=value, **common)
        if ioc_type == "sha256":
            return stix2.File(hashes={"SHA-256": value}, **common)
        if ioc_type == "url":
            return stix2.URL(value=value, **common)
        if ioc_type == "email":
            return stix2.EmailAddress(value=value, **common)
    except Exception:
        pass
    return None


def _get_pattern(ioc_type: str, value: str) -> str | None:
    """Return the STIX 2.1 pattern string for the given IOC type and value."""
    v = _stix_escape(value)
    patterns: dict[str, str] = {
        "domain": f"[domain-name:value = '{v}']",
        "ip": f"[ipv4-addr:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
    }
    return patterns.get(ioc_type)


def _make_indicator(
    pattern: str,
    ioc_type: str,
    value: str,
    valid_from: datetime,
    author: stix2.Identity,
    tlp_marking: stix2.MarkingDefinition,
    score: int,
) -> stix2.Indicator:
    """Create a STIX Indicator with a deterministic ID derived from the pattern."""
    opencti_type = IOC_TYPE_TO_OPENCTI_TYPE.get(ioc_type, "Unknown")
    return stix2.Indicator(
        id=PyCTIIndicator.generate_id(pattern),
        name=value,
        description=f"Malicious {ioc_type} observed in Cyware CSAP.",
        pattern=pattern,
        pattern_type="stix",
        valid_from=valid_from,
        created_by_ref=author.id,
        object_marking_refs=[tlp_marking],
        labels=["malicious-activity"],
        custom_properties={
            "x_opencti_score": score,
            "x_opencti_main_observable_type": opencti_type,
        },
        allow_custom=True,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_ioc_objects(
    ioc_type: str,
    value: str,
    is_blacklisted: bool,
    score: int,
    valid_from: datetime,
    author: stix2.Identity,
    tlp_marking: stix2.MarkingDefinition,
) -> list:
    """Create STIX objects for a single IOC value.

    Returns a list of stix2 objects ready for inclusion in a bundle:
    - Blacklisted: [Observable, Indicator, Relationship(based-on)]
    - Whitelisted: [Observable]
    - Unknown type or invalid value: []
    """
    if not value or not value.strip():
        return []

    value = value.strip()

    observable = _make_observable(ioc_type, value, author, tlp_marking, score)
    if observable is None:
        return []

    objects: list = [observable]

    if is_blacklisted:
        pattern = _get_pattern(ioc_type, value)
        if pattern is None:
            return objects  # Observable only — can't build a pattern for this type

        indicator = _make_indicator(
            pattern=pattern,
            ioc_type=ioc_type,
            value=value,
            valid_from=valid_from,
            author=author,
            tlp_marking=tlp_marking,
            score=score,
        )
        objects.append(indicator)

        relationship = stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            created_by_ref=author.id,
            object_marking_refs=[tlp_marking],
        )
        objects.append(relationship)

    return objects
