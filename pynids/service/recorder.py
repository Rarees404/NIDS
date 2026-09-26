"""
Rolling PCAP recorder.

Keeps the last N capture files of M megabytes each, so there is always a
recent window of raw traffic to open in Wireshark — and, together with a
browser's ``SSLKEYLOGFILE``, to decrypt (see ``pynids decrypt``).
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


class PcapRing:
    def __init__(self, directory: Path, max_mb: int = 50, max_files: int = 10, prefix: str = "pynids") -> None:
        from scapy.utils import PcapWriter

        self._writer_cls = PcapWriter
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_mb * 1024 * 1024
        self.max_files = max_files
        self.prefix = prefix
        self._lock = threading.Lock()
        self._writer: Any = None
        self._path: Optional[Path] = None
        self._written = 0
        self._rotate()

    def _rotate(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:  # noqa: BLE001
                pass
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self._path = self.directory / f"{self.prefix}-{stamp}-{int(time.time() * 1000) % 1000:03d}.pcap"
        self._writer = self._writer_cls(str(self._path), append=False, sync=False)
        self._written = 0
        files: List[Path] = sorted(self.directory.glob(f"{self.prefix}-*.pcap"))
        for old in files[:-self.max_files]:
            try:
                old.unlink()
            except OSError:
                pass

    def write(self, pkt: Any) -> None:
        with self._lock:
            try:
                self._writer.write(pkt)
                self._written += len(pkt)
            except Exception as exc:  # noqa: BLE001
                logger.debug("PCAP write failed: %s", exc)
                return
            if self._written >= self.max_bytes:
                self._rotate()

    def close(self) -> None:
        with self._lock:
            if self._writer is not None:
                self._writer.close()
                self._writer = None

    @property
    def current(self) -> Optional[Path]:
        return self._path
