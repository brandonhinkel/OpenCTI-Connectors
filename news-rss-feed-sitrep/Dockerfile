FROM python:3.12-slim

# Build deps for wheels that compile native extensions
# (curl_cffi, lxml, some torch dependencies)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libxml2-dev \
    libxslt-dev \
    libffi-dev \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/opencti-connector-rss

# Install dependencies before copying source so the layer is cached on rebuilds
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector source
COPY src/ ./src/

# Config is mounted at runtime — not baked into the image.
# Default path: /opt/opencti-connector-rss/config.yml (set CONFIG_PATH to override).
# Mount example:
#   volumes:
#     - ./config.yml:/opt/opencti-connector-rss/config.yml:ro
#
# Hugging Face model cache is also expected to be a persistent volume so models
# are not re-downloaded on every container restart:
#   volumes:
#     - hf_cache:/root/.cache/huggingface

ENTRYPOINT ["python", "src/connector.py"]
