from pydantic import Field, PositiveInt
from src.models.configs import ConfigBaseSettings

F3_STIX_FILE_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json"


class _ConfigLoaderF3(ConfigBaseSettings):
    """Interface for loading dedicated F3 configuration."""

    interval: PositiveInt = Field(
        default=7,
        description=(
            "Polling interval in days for fetching and refreshing F3 data. "
            "Determines how often the system checks for updates to the Fight Fraud Framework dataset."
        ),
    )
    file_url: str = Field(
        default=F3_STIX_FILE_URL,
        description=(
            "URL to the MITRE Fight Fraud Framework (F3) STIX 2.1 JSON bundle. "
            "Contains tactics, techniques, and procedures (TTPs) used by financial fraud actors."
        ),
    )
