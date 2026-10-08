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
        self.linktype = 1  # Ethernet until the first frame says otherwise
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
        # Set directly: scapy treats linktype=0 (DLT_NULL, i.e. lo0) as "unset".
        self._writer.linktype = self.linktype
        self._written = 0
        files: List[Path] = sorted(self.directory.glob(f"{self.prefix}-*.pcap"))
        for old in files[:-self.max_files]:
            try:
                old.unlink()
            except OSError:
                pass

    def write(self, frame: bytes, ts: Optional[float] = None, linktype: int = 1) -> None:
        """Append one raw captured frame (the sniffer's ``raw_callback``)."""
        with self._lock:
            if linktype != self.linktype:
                self.linktype = linktype  # a pcap file holds a single link type
                self._rotate()
            try:
                if not self._writer.header_present:
                    self._writer.write_header(frame)
                if ts is None:
                    ts = time.time()
                sec = int(ts)  # scapy zeroes usec when only a float sec is given
                self._writer.write_packet(frame, sec=sec, usec=int(round((ts - sec) * 1e6)))
                self._written += len(frame)
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
