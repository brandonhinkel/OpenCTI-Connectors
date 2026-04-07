"""Abstract base importer for Cyware CSAP connector."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional

import stix2

if TYPE_CHECKING:
    from cyware_csap_connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class BaseImporter(ABC):
    """Abstract base for all Cyware CSAP importers."""

    _NAME: Optional[str] = None

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        author: stix2.Identity,
        tlp_marking: stix2.MarkingDefinition,
    ) -> None:
        self.config = config
        self.helper = helper
        self.author = author
        self.tlp_marking = tlp_marking
        self.work_id: Optional[str] = None

    def start(self, work_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """Called by the connector to begin an import run."""
        self.work_id = work_id
        return self.run(state)

    @abstractmethod
    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Perform the import and return updated state dict."""
        ...

    @property
    def name(self) -> Optional[str]:
        return self._NAME

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        self.helper.send_stix2_bundle(
            bundle.serialize(),
            work_id=self.work_id,
            bypass_split=True,
        )

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.helper.set_state(state)

    def _source_name(self) -> str:
        return self.author["name"]

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _info(self, msg: str, *args: Any) -> None:
        self.helper.log_info(msg.format(*args))

    def _debug(self, msg: str, *args: Any) -> None:
        self.helper.log_debug(msg.format(*args))

    def _warning(self, msg: str, *args: Any) -> None:
        self.helper.log_warning(msg.format(*args))

    def _error(self, msg: str, *args: Any) -> None:
        self.helper.log_error(msg.format(*args))
