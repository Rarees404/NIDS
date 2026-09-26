"""
SQLite persistence backend for PyNIDS alerts.

Stores each alert in a normalised schema that supports:
- Full-text search via SQLite FTS5 on the message column
- Indexed lookups by src_ip, dst_ip, severity, alert_type, and timestamp
- Simple CLI query support (``pynids query``)

Schema
------
The ``alerts`` table uses a wide, denormalised layout for simplicity.
Evidence is stored as a JSON string in a separate ``evidence`` column.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Optional

from ..manager import BaseOutput
from ..model import Alert, Severity

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    timestamp       REAL NOT NULL,
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    severity_numeric INTEGER NOT NULL,
    message         TEXT NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    rule_id         TEXT,
    flow_id         TEXT,
    confidence      REAL,
    tags            TEXT,
    mitre_technique TEXT,
    evidence        TEXT,
    app             TEXT,
    process_name    TEXT,
    pid             INTEGER,
    remote_host     TEXT,
    country         TEXT,
    context         TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip      ON alerts (dst_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts (severity_numeric);
CREATE INDEX IF NOT EXISTS idx_alerts_type        ON alerts (alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_rule        ON alerts (rule_id);

CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts USING fts5 (
    alert_id UNINDEXED,
    message,
    src_ip,
    dst_ip,
    tags,
    content='alerts',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS alerts_ai AFTER INSERT ON alerts BEGIN
    INSERT INTO alerts_fts (rowid, alert_id, message, src_ip, dst_ip, tags)
    VALUES (new.rowid, new.alert_id, new.message, new.src_ip, new.dst_ip, new.tags);
END;
"""

# Columns added after the first release — added in place to older databases.
_MIGRATIONS = (
    ("app", "TEXT"),
    ("process_name", "TEXT"),
    ("pid", "INTEGER"),
    ("remote_host", "TEXT"),
    ("country", "TEXT"),
    ("context", "TEXT"),
)

_POST_MIGRATION_DDL = """
CREATE INDEX IF NOT EXISTS idx_alerts_app ON alerts (app);
"""

_INSERT = """
INSERT OR IGNORE INTO alerts
  (alert_id, timestamp, alert_type, severity, severity_numeric, message,
   src_ip, dst_ip, src_port, dst_port, protocol, rule_id, flow_id,
   confidence, tags, mitre_technique, evidence,
   app, process_name, pid, remote_host, country, context)
VALUES
  (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class SQLiteOutput(BaseOutput):
    """
    Persist alerts to a SQLite database with FTS5 full-text search.

    Args:
        path:          File path for the SQLite database.
        min_severity:  Only persist alerts at or above this level.
        batch_size:    Number of alerts to buffer before committing (0 = autocommit).
    """

    def __init__(
        self,
        path: str,
        min_severity: Severity = Severity.LOW,
        batch_size: int = 50,
        flush_interval: float = 2.0,
    ) -> None:
        self.path = path
        self.min_severity = min_severity
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        # WAL lets the API server read while the capture thread writes.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_DDL)
        self._migrate()
        self._conn.commit()
        self._pending: List[tuple] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()

    def _migrate(self) -> None:
        existing = {row[1] for row in self._conn.execute("PRAGMA table_info(alerts)")}
        for column, sql_type in _MIGRATIONS:
            if column not in existing:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {sql_type}")
        self._conn.executescript(_POST_MIGRATION_DDL)

    def emit(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        d = alert.to_dict()
        ctx = d.get("context") or {}
        row = (
            d["alert_id"],
            d["timestamp"],
            d["alert_type"],
            d["severity"],
            d["severity_numeric"],
            d["message"],
            d["src_ip"],
            d["dst_ip"],
            d["src_port"],
            d["dst_port"],
            d["protocol"],
            d["rule_id"],
            d["flow_id"],
            d["confidence"],
            json.dumps(d["tags"]),
            d["mitre_technique"],
            json.dumps(d["evidence"], default=str),
            ctx.get("app"),
            ctx.get("process"),
            ctx.get("pid"),
            ctx.get("remote_host"),
            ctx.get("country"),
            json.dumps(ctx, default=str),
        )
        with self._lock:
            self._pending.append(row)
            due = (
                self.batch_size == 0
                or len(self._pending) >= self.batch_size
                or time.monotonic() - self._last_flush >= self.flush_interval
            )
            if due:
                self._flush()

    def flush(self) -> None:
        """Commit any buffered alerts now (called periodically by the daemon)."""
        with self._lock:
            self._flush()

    def close(self) -> None:
        self.flush()
        try:
            self._conn.close()
        except Exception:
            pass

    def query(
        self,
        min_severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        alert_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """Simple programmatic query helper."""
        conditions = []
        params: List = []
        if min_severity:
            sev_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            n = sev_map.get(min_severity.upper(), 1)
            conditions.append("severity_numeric >= ?")
            params.append(n)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
        if alert_type:
            conditions.append("alert_type = ?")
            params.append(alert_type)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cur = self._conn.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def _flush(self) -> None:
        self._last_flush = time.monotonic()
        if not self._pending:
            return
        try:
            self._conn.executemany(_INSERT, self._pending)
            self._conn.commit()
        except sqlite3.Error as exc:
            logger.error("SQLiteOutput flush error: %s", exc)
        finally:
            self._pending.clear()
