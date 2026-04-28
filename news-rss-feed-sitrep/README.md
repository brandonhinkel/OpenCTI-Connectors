# OpenCTI RSS Threat Intelligence SITREP Connector

An OpenCTI external-import connector that aggregates cybersecurity news from RSS feeds, extracts threat intelligence, and generates a daily SITREP (Situation Report) report inside the platform.

## Overview

Each run the connector:

1. Fetches articles from 19+ RSS feeds (Krebs, Bleeping Computer, CISA, Talos, Unit 42, etc.)
2. Filters articles for cybersecurity relevance using a zero-shot NLI classifier (DeBERTa)
3. Extracts entities — CVEs, ATT&CK techniques, threat actors, malware, victim organizations — via GLiNER NER and regex
4. Scrapes full article text for enrichment
5. Embeds articles with a sentence transformer and clusters related stories
6. Classifies each cluster into a SITREP category (Cyber Threats, Fraud, AI Threats, Supply Chain, Insider Threats)
7. Generates an HTML SITREP report and ingests it as an OpenCTI Report object with associated STIX relationships

## Requirements

### Hardware

The pipeline loads several ML models at startup:

| Model | Purpose | Size |
|---|---|---|
| `all-MiniLM-L6-v2` | Article embeddings | ~90 MB |
| `urchade/gliner_medium-v2.1` | Named entity recognition | ~200 MB |
| `MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli` | Relevance classification | ~700 MB |
| `sshleifer/distilbart-cnn-12-6` *(optional)* | Abstractive summarization | ~600 MB |

**Minimum recommended:** 4 GB RAM, 4 CPU cores. GPU is not required; all models run on CPU by default.

Models are downloaded from Hugging Face on first run and cached. Mount a persistent volume at `/root/.cache/huggingface` to avoid re-downloading on container restart.

### Software

- Python 3.12+
- OpenCTI platform 6.x with a valid API token

## Configuration

Configuration is split between **environment variables** (connection/identity) and **`config.yml`** (pipeline behavior).

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | — | OpenCTI platform URL |
| `OPENCTI_TOKEN` | Yes | — | OpenCTI API token |
| `CONNECTOR_ID` | Yes | — | Unique UUIDv4 for this connector instance |
| `CONNECTOR_NAME` | No | `RSS Threat Intelligence SITREP` | Display name in OpenCTI |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `CONNECTOR_DURATION_PERIOD` | No | `PT2H` | Run interval as ISO 8601 duration |
| `RSS_CONNECTOR_CONFIDENCE` | No | `50` | Override `confidence` from config.yml |
| `RSS_CONNECTOR_TLP` | No | `WHITE` | Override `tlp` from config.yml |

### config.yml

Mount `config.yml` into the container at `/opt/opencti-connector-rss/config.yml` (or set `CONFIG_PATH` to override the path). Key sections:

```yaml
rss_connector:
  # Relevance filtering
  relevance_threshold: 0.55        # NLI confidence cutoff (0–1)
  relevance_skip_if_has_entities: true  # skip NLI if CVE/ATT&CK found

  # Full-text scraping
  scraping_enabled: true
  scrape_timeout: 15               # seconds per article

  # NER
  gliner_enabled: true
  ner_model: "urchade/gliner_medium-v2.1"

  # Clustering
  cluster_min_similarity: 0.72
  cluster_window_days: 2           # max days between articles to be grouped

  # SITREP classification
  sitrep_threshold: 0.40

  # Feeds list (URL strings or dicts with per-feed overrides)
  feeds:
    - "https://krebsonsecurity.com/feed/"
    - url: "https://unit42.paloaltonetworks.com/category/threat-research/feed/"
      name: "Unit 42"
      max_age_days: 14             # research blogs publish infrequently
```

See [`config.yml`](config.yml) for the full list of options and all default values.

## Deployment

### Docker (recommended)

1. Copy `.env.example` to `.env` and fill in your OpenCTI credentials:

   ```
   OPENCTI_URL=http://opencti:8080
   OPENCTI_TOKEN=<your-api-token>
   CONNECTOR_RSS_ID=<uuidv4>
   ```

2. Edit `config.yml` as needed (feeds list, thresholds, etc.).

3. Update the network name in `docker-compose.yml` to match your OpenCTI deployment's Docker network.

4. Start the connector:

   ```bash
   docker compose up --build -d
   ```

### Running Locally

```bash
cd news-rss-feed-sitrep
pip install -r requirements.txt

# Set required env vars
export OPENCTI_URL=http://opencti:8080
export OPENCTI_TOKEN=<your-api-token>
export CONNECTOR_ID=<uuidv4>

# Run once
python src/connector.py
```

## Output

Each run produces one OpenCTI **Report** object named `SITREP — <date>` containing:

- An HTML body organized by threat category (Cyber Threats, Fraud, AI Threats, Supply Chain, Insider Threats)
- Cluster cards summarizing related articles with entity badges (actors, malware, CVEs, techniques, victims)
- Sub-events partitioned by victim organization where applicable
- STIX relationships linking the report to ingested observables and platform entities (IntrusionSets, Malware, etc.)

If a SITREP for the current date already exists it is updated in place (`update=True`).
