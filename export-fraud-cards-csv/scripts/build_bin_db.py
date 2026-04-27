#!/usr/bin/env python3
"""
Convert BIN list CSV to a SQLite database for fast key/value lookups.

Usage:
    python3 build_bin_db.py <input.csv> [output.db]

The default output path is bin_lookup.db in the current directory.

Expected CSV columns (from https://github.com/binlist/data):
    BIN, Brand, Type, Category, Issuer, IssuerPhone, IssuerUrl,
    isoCode2, isoCode3, CountryName

To use with Docker, mount the generated DB file as a volume:
    docker run -v /path/to/bin_lookup.db:/data/bin_lookup.db ...
Or pass a custom path via environment variable:
    docker run -e EXPORT_FRAUD_CARDS_BIN_DB_PATH=/custom/path/bin.db ...
"""
import csv
import sqlite3
import sys
from pathlib import Path

CREATE_TABLE = """
CREATE TABLE bins (
    bin           TEXT PRIMARY KEY,
    brand         TEXT NOT NULL DEFAULT '',
    type          TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL DEFAULT '',
    issuer        TEXT NOT NULL DEFAULT '',
    issuer_phone  TEXT NOT NULL DEFAULT '',
    issuer_url    TEXT NOT NULL DEFAULT '',
    iso_code2     TEXT NOT NULL DEFAULT '',
    iso_code3     TEXT NOT NULL DEFAULT '',
    country_name  TEXT NOT NULL DEFAULT ''
)
"""

INSERT_ROW = """
INSERT OR REPLACE INTO bins
    (bin, brand, type, category, issuer, issuer_phone, issuer_url, iso_code2, iso_code3, country_name)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

BATCH_SIZE = 10_000


def build_bin_db(csv_path: str, db_path: str) -> None:
    print(f"Reading BIN data from {csv_path} ...")
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS bins")
        cursor.execute(CREATE_TABLE)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bin ON bins (bin)")

        total = 0
        batch: list[tuple] = []

        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                batch.append((
                    row["BIN"].strip().zfill(6),
                    row.get("Brand", "").strip(),
                    row.get("Type", "").strip(),
                    row.get("Category", "").strip(),
                    row.get("Issuer", "").strip(),
                    row.get("IssuerPhone", "").strip(),
                    row.get("IssuerUrl", "").strip(),
                    row.get("isoCode2", "").strip(),
                    row.get("isoCode3", "").strip(),
                    row.get("CountryName", "").strip(),
                ))
                if len(batch) >= BATCH_SIZE:
                    cursor.executemany(INSERT_ROW, batch)
                    total += len(batch)
                    batch = []
                    print(f"  {total:,} rows inserted...", end="\r")

        if batch:
            cursor.executemany(INSERT_ROW, batch)
            total += len(batch)

        conn.commit()
        print(f"\nDone — {total:,} BIN records written to {db_path}")
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    csv_path = sys.argv[1]
    db_path = sys.argv[2] if len(sys.argv) > 2 else "bin_lookup.db"

    if not Path(csv_path).is_file():
        print(f"Error: CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    build_bin_db(csv_path, db_path)
