"""
Rotating JSON-lines file output for PyNIDS.

Each alert is written as a single JSON object on its own line (NDJSON /
JSON Lines format), making logs trivially parseable by ``jq``, Splunk,
Elasticsearch, and other SIEM tools.

Log rotation is handled by Python's standard
:class:`logging.handlers.RotatingFileHandler` logic, reimplemented here
directly so the output file does not mix with the application's log
stream.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from ..manager import BaseOutput
from ..model import Alert, Severity


class JsonFileOutput(BaseOutput):
    """
    Append-mode JSON Lines file writer with size-based rotation.

    Args:
        path:         File path where alerts are written.
        max_bytes:    Maximum file size before rotation (default 10 MiB).
        backup_count: Number of rotated files to keep (default 5).
        min_severity: Only write alerts at or above this severity.
    """

    _DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB

    def __init__(
        self,
        path: str,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        backup_count: int = 5,
        min_severity: Severity = Severity.LOW,
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.min_severity = min_severity
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def emit(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        line = json.dumps(alert.to_dict(), ensure_ascii=False) + "\n"
        self._fh.write(line)
        self._fh.flush()
        self._maybe_rotate()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def _maybe_rotate(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size < self.max_bytes:
            return

        self._fh.close()
        # Shift existing backups
        for i in range(self.backup_count - 1, 0, -1):
            src = Path(f"{self.path}.{i}")
            dst = Path(f"{self.path}.{i + 1}")
            if src.exists():
                src.rename(dst)
        rotated = Path(f"{self.path}.1")
        try:
            self.path.rename(rotated)
        except OSError:
            pass
        self._fh = self.path.open("a", encoding="utf-8")
