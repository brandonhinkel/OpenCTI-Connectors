import os
import sqlite3
import threading


class BinLookup:
    """SQLite-backed BIN (Bank Identification Number) lookup.

    Thread-safe: each thread gets its own connection via threading.local.
    If the database file is absent, all lookups return an empty dict and
    the connector continues without BIN enrichment.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.available = os.path.isfile(db_path)
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def lookup(self, card_number: str) -> dict:
        """Return BIN metadata for the first 6 digits of card_number, or {}."""
        if not self.available:
            return {}
        bin6 = card_number[:6].zfill(6)
        try:
            row = self._conn().execute(
                "SELECT * FROM bins WHERE bin = ?", (bin6,)
            ).fetchone()
            if row:
                return dict(row)
        except Exception:
            pass
        return {}
