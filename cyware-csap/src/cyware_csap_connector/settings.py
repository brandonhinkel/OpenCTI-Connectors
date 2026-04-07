"""Connector configuration and settings."""

from datetime import datetime, timedelta, timezone
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, PositiveInt, SecretStr, field_validator


def _default_timestamp_30_days_ago() -> int:
    """Return Unix timestamp for 30 days ago."""
    return int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp())


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level config (CONNECTOR_* environment variables)."""

    id: str = Field(
        default="cyware-csap--00000000-0000-0000-0000-000000000000",
        description="Unique UUIDv4 identifier for this connector instance.",
    )
    name: str = Field(
        default="Cyware CSAP",
        description="Connector display name in OpenCTI.",
    )
    scope: ListFromString = Field(
        default=["cyware-csap"],
        description="Connector scope.",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=1),
        description="Run interval in ISO 8601 duration format (e.g. PT1H).",
    )


class CywareConfig(BaseConfigModel):
    """Cyware CSAP-specific config (CYWARE_* environment variables)."""

    base_url: str = Field(
        description=(
            "CSAP API base URL. Must end with /. "
            "Example: https://csap-01.cyware.com/api/"
        ),
    )
    access_id: SecretStr = Field(description="API access ID.")
    access_secret: SecretStr = Field(description="API secret key for HMAC-SHA1 signing.")
    tlp: Literal["red", "amber+strict", "amber", "green", "clear", "white"] = Field(
        default="amber+strict",
        description="Default TLP marking applied when an alert has no TLP field.",
    )
    scopes: ListFromString = Field(
        default=["alert", "intel"],
        description="Comma-separated list of importers to run. Available: alert, intel.",
    )

    # Alert ingestion
    alert_start_timestamp: int = Field(
        default_factory=_default_timestamp_30_days_ago,
        description=(
            "EPOCH timestamp to begin importing alerts from. "
            "Default: 30 days ago. WARNING: 0 means ALL alerts."
        ),
    )
    alert_category_ids: ListFromString = Field(
        default=[],
        description="Comma-separated Cyware category IDs to filter alerts. Empty = all categories.",
    )
    alert_tlp_filter: ListFromString = Field(
        default=[],
        description="Comma-separated TLP values to filter alerts (e.g. GREEN,AMBER). Empty = all TLPs.",
    )
    alert_page_size: PositiveInt = Field(
        default=50,
        description="Number of alerts to fetch per page.",
    )

    # Intel ingestion
    intel_page_size: PositiveInt = Field(
        default=50,
        description="Number of intel reports to fetch per page.",
    )

    # IOC scoring — only applies to IOCs embedded in alert/intel report bundles
    indicator_blacklist_score: PositiveInt = Field(
        default=75,
        description="x_opencti_score for malicious (blacklisted) IOCs tied to a report.",
    )
    indicator_whitelist_score: PositiveInt = Field(
        default=15,
        description="x_opencti_score for whitelisted IOCs (context only, no indicator pattern).",
    )

    @field_validator("tlp", mode="before")
    @classmethod
    def lowercase_tlp(cls, v: str) -> str:
        return v.lower()

    @field_validator("base_url", mode="after")
    @classmethod
    def ensure_trailing_slash(cls, v: str) -> str:
        return v if v.endswith("/") else v + "/"


class ConnectorSettings(BaseConnectorSettings):
    """Root settings — combines connector-level and Cyware-specific configs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig,
    )
    cyware: CywareConfig = Field(default_factory=CywareConfig)
