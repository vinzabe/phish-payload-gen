"""Durable engagement + click log, so a simulation is auditable and results feed
training assignment — never discipline."""
from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
    tracking_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
    target TEXT NOT NULL, template_id TEXT NOT NULL, generated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, tracking_id TEXT NOT NULL,
    at TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: Path | str) -> None:
        self._c = sqlite3.connect(Path(path), isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.executescript(_SCHEMA)
        row = self._c.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self._c.execute("INSERT INTO meta VALUES('schema_version',?)",
                            (str(SCHEMA_VERSION),))
        elif int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError(f"store schema {row['value']} != {SCHEMA_VERSION}")

    def close(self) -> None:
        self._c.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *e: object) -> None:
        self.close()

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.UTC).isoformat()

    def record_artifact(self, tracking_id: str, engagement_id: str,
                        target: str, template_id: str) -> None:
        self._c.execute(
            "INSERT INTO artifacts VALUES(?,?,?,?,?) "
            "ON CONFLICT(tracking_id) DO NOTHING",
            (tracking_id, engagement_id, target, template_id, self._now()))

    def record_click(self, tracking_id: str) -> bool:
        """Log a click. Returns False for an unknown tracking id (so a random
        probe cannot create phantom results)."""
        row = self._c.execute("SELECT 1 FROM artifacts WHERE tracking_id=?",
                             (tracking_id,)).fetchone()
        if row is None:
            return False
        self._c.execute("INSERT INTO clicks(tracking_id,at) VALUES(?,?)",
                        (tracking_id, self._now()))
        return True

    def click_rate(self, engagement_id: str) -> tuple[int, int]:
        sent = self._c.execute(
            "SELECT COUNT(*) AS n FROM artifacts WHERE engagement_id=?",
            (engagement_id,)).fetchone()["n"]
        clicked = self._c.execute(
            "SELECT COUNT(DISTINCT a.tracking_id) AS n FROM artifacts a "
            "JOIN clicks c ON c.tracking_id = a.tracking_id "
            "WHERE a.engagement_id=?", (engagement_id,)).fetchone()["n"]
        return clicked, sent
