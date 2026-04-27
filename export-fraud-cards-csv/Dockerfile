FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE

# Copy connector source and the DB build script
COPY src /opt/opencti-connector-export-fraud-cards-csv
COPY scripts /opt/opencti-connector-export-fraud-cards-csv/scripts

# Install Python dependencies
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-export-fraud-cards-csv && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Mount the BIN lookup database here (or copy it in at build time).
# Generate it first with:
#   python3 scripts/build_bin_db.py /path/to/bin-list-data.csv bin_lookup.db
# Then mount: -v /local/path/bin_lookup.db:/data/bin_lookup.db
VOLUME ["/data"]

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
