"""OpenCTI Cyware CSAP connector entry point."""

import traceback

from cyware_csap_connector import ConnectorSettings, CywareCSAP
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = CywareCSAP(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
