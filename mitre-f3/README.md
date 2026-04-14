# OpenCTI MITRE Fight Fraud Framework (F3) Connector

An OpenCTI external-import connector that ingests the [MITRE Fight Fraud Framework (F3)](https://github.com/center-for-threat-informed-defense/fight-fraud-framework) — a curated knowledge base of tactics, techniques, and procedures (TTPs) used by financial fraud actors.

## Overview

The F3 framework is published by the [Center for Threat-Informed Defense (CTID)](https://ctid.mitre.org/) and follows the MITRE ATT&CK data model. This connector fetches the official STIX 2.1 bundle from the F3 GitHub repository and imports it into OpenCTI, populating:

- **7 Tactics** (`x-mitre-tactic`): Reconnaissance, Resource Development, Initial Access, Defense Evasion, Positioning, Execution, Monetization
- **95+ Techniques / Subtechniques** (`attack-pattern`)
- **Kill chain**: `mitre-f3` (and a versioned variant, e.g. `mitre-f3-v1`)
- **Matrix and Collection** objects (`x-mitre-matrix`, `x-mitre-collection`)

## Configuration

Configuration is read from environment variables, a `.env` file, or a `config.yml` (in that priority order).

| Variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | — | OpenCTI platform URL |
| `OPENCTI_TOKEN` | — | OpenCTI API token |
| `CONNECTOR_ID` | — | Unique UUIDv4 for this connector instance |
| `CONNECTOR_NAME` | `MITRE Fight Fraud Framework (F3)` | Display name in OpenCTI |
| `CONNECTOR_SCOPE` | `attack-pattern,relationship,...` | STIX types to import |
| `CONNECTOR_LOG_LEVEL` | `error` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `F3_INTERVAL` | `7` | Polling interval in days |
| `F3_FILE_URL` | F3 GitHub raw URL | Override the STIX bundle source URL |

See `src/config.yml.sample` for the YAML equivalent.

## Deployment

### Docker

```bash
docker build -t connector-mitre-f3:latest .
docker-compose up -d
```

Set at minimum `OPENCTI_URL`, `OPENCTI_TOKEN`, and `CONNECTOR_ID` before starting.

### Local

```bash
cd src
pip install -r requirements.txt
# Copy and edit config
cp config.yml.sample config.yml
python -m src
```
