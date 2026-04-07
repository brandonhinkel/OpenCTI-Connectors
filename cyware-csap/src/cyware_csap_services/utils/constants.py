"""Shared constants, TLP mappings, and utilities for the Cyware CSAP connector."""

from __future__ import annotations

from html.parser import HTMLParser

import stix2

# ---------------------------------------------------------------------------
# TLP Markings
# ---------------------------------------------------------------------------

# TLP:AMBER+STRICT (TLP 2.0) — uses OpenCTI's seeded marking definition ID.
# StatementMarking is used because stix2 library does not natively support
# the "amber+strict" TLP value. OpenCTI matches by ID, so the definition
# type is not critical for platform recognition.
_TLP_AMBER_STRICT = stix2.MarkingDefinition(
    id="marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    definition_type="statement",
    definition=stix2.StatementMarking(statement="TLP:AMBER+STRICT"),
    allow_custom=True,
)

# Cyware alert `tlp` field value (uppercase) → stix2 MarkingDefinition
CYWARE_TLP_MAP: dict[str, stix2.MarkingDefinition] = {
    "WHITE": stix2.TLP_WHITE,
    "CLEAR": stix2.TLP_WHITE,
    "GREEN": stix2.TLP_GREEN,
    "AMBER": stix2.TLP_AMBER,
    "AMBER+STRICT": _TLP_AMBER_STRICT,
    "RED": stix2.TLP_RED,
}

# Connector config `tlp` value (lowercase) → stix2 MarkingDefinition
CONFIG_TLP_MAP: dict[str, stix2.MarkingDefinition] = {
    "white": stix2.TLP_WHITE,
    "clear": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": _TLP_AMBER_STRICT,
    "red": stix2.TLP_RED,
}

# Cyware indicator type key → OpenCTI observable type name
# Used to set x_opencti_main_observable_type on Indicator objects.
IOC_TYPE_TO_OPENCTI_TYPE: dict[str, str] = {
    "domain": "Domain-Name",
    "ip": "IPv4-Addr",
    "sha256": "StixFile",
    "url": "Url",
    "email": "Email-Addr",
}


# ---------------------------------------------------------------------------
# TLP resolution helper
# ---------------------------------------------------------------------------

def get_tlp_marking(
    cyware_tlp: str | None,
    default: stix2.MarkingDefinition,
) -> stix2.MarkingDefinition:
    """Resolve a Cyware alert TLP string to a stix2 MarkingDefinition.

    Falls back to `default` if the value is absent or unrecognised.
    """
    if not cyware_tlp:
        return default
    return CYWARE_TLP_MAP.get(cyware_tlp.upper().strip(), default)


# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------

class _HTMLStripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self._parts.append(stripped)

    def get_text(self) -> str:
        return " ".join(self._parts)


def strip_html(html_str: str | None) -> str:
    """Strip HTML tags and return plain text.

    Returns an empty string for None or empty input. Falls back to the
    original string if parsing fails.
    """
    if not html_str:
        return ""
    try:
        stripper = _HTMLStripper()
        stripper.feed(html_str)
        return stripper.get_text()
    except Exception:
        return html_str or ""
