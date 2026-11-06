"""
RFC 5424 Syslog output backend for PyNIDS.

Emits alerts as structured syslog messages compatible with any syslog
daemon (rsyslog, syslog-ng, journald) and SIEM ingestion pipelines.

The structured-data element ``[pynids@0]`` carries the alert's core
fields as SD-PARAMs so they survive log aggregation without requiring
JSON parsing.

Example syslog line (line-wrapped for readability)::

    <147>1 2024-01-15T14:32:11.000Z ids-host pynids - -
    [pynids@0 severity="HIGH" type="signature" rule="SIG-004"
     src="10.0.0.5" dst="192.168.1.10" mitre="T1046"]
    Port scan from 10.0.0.5 → 192.168.1.10

Facility codes follow RFC 5424 §6.2.1.
"""
from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

from ..manager import BaseOutput
from ..model import Alert, Severity

logger = logging.getLogger(__name__)

# RFC 5424 facility × severity → PRI value
_FACILITY_SECURITY = 4   # security/authorization messages (facility 4)
_SEVERITY_MAP = {
    Severity.LOW:      6,  # informational
    Severity.MEDIUM:   5,  # notice
    Severity.HIGH:     4,  # warning
    Severity.CRITICAL: 2,  # critical
}

_STOP = object()


def _sd_escape(value: str) -> str:
    """Escape SD-PARAM value per RFC 5424 §6.3.3."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


class SyslogOutput(BaseOutput):
    """
    Send alerts to a syslog receiver over UDP or TCP (IPv4 or IPv6).

    ``emit`` only formats and queues the message; a worker thread does the
    network I/O, so an unreachable or slow receiver never stalls capture.
    When the queue (``queue_size``) is full the alert is dropped and
    counted.  A failed connection is retried with exponential backoff
    (``retry_initial`` … ``retry_max`` seconds) on later sends; failures
    are logged at most once per backoff period.

    Args:
        host:         Syslog server hostname or IP.
        port:         Syslog server port (default 514).
        protocol:     ``'udp'`` (default) or ``'tcp'``.
        facility:     RFC 5424 facility code (default 4 = security).
        app_name:     APPNAME field in syslog header (default ``'pynids'``).
        hostname:     HOSTNAME field (default: local hostname).
        min_severity: Only emit alerts at or above this severity.
        timeout:      Socket connect / send timeout in seconds.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        protocol: str = "udp",
        facility: int = _FACILITY_SECURITY,
        app_name: str = "pynids",
        hostname: Optional[str] = None,
        min_severity: Severity = Severity.LOW,
        timeout: float = 2.0,
        queue_size: int = 10_000,
        retry_initial: float = 1.0,
        retry_max: float = 60.0,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.facility = facility
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()
        self.min_severity = min_severity
        self.timeout = timeout
        self.retry_initial = retry_initial
        self.retry_max = retry_max
        self.dropped = 0
        self.sent = 0
        self._sock: Optional[socket.socket] = None
        self._addr: Optional[Tuple] = None
        self._backoff = retry_initial
        self._next_attempt = 0.0
        self._queue: "queue.Queue" = queue.Queue(maxsize=max(1, queue_size))
        self._closed = False
        self._connect()
        self._worker = threading.Thread(target=self._run, name="pynids-syslog", daemon=True)
        self._worker.start()

    def emit(self, alert: Alert) -> None:
        if alert.severity < self.min_severity or self._closed:
            return
        msg = self._format(alert).encode("utf-8", errors="replace")
        try:
            self._queue.put_nowait(msg)
        except queue.Full:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                logger.warning("SyslogOutput: queue full, %d alert(s) dropped", self.dropped)

    def flush(self, timeout: float = 5.0) -> None:
        """Wait (up to *timeout* s) until every queued message was handled."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.flush()
        try:
            # Never block shutdown: a stalled receiver can leave the queue full.
            self._queue.put(_STOP, timeout=1.0)
        except queue.Full:
            logger.warning("SyslogOutput: %d alert(s) still queued at shutdown were not sent",
                           self._queue.qsize())
        self._worker.join(timeout=self.timeout + 1)
        self._disconnect()

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self._send(item)
            except Exception as exc:  # noqa: BLE001 — the worker must survive
                logger.debug("SyslogOutput worker error: %s", exc)
            finally:
                self._queue.task_done()

    def _disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _connect(self) -> bool:
        """(Re)open the socket unless still backing off.  Returns True when connected."""
        if self._sock is not None:
            return True
        now = time.monotonic()
        if now < self._next_attempt:
            return False
        kind = socket.SOCK_STREAM if self.protocol == "tcp" else socket.SOCK_DGRAM
        last_exc: Optional[OSError] = None
        try:
            infos = socket.getaddrinfo(self.host, self.port, 0, kind)
        except OSError as exc:
            infos, last_exc = [], exc
        for family, socktype, proto, _, addr in infos:
            sock = None
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.timeout)
                if self.protocol == "tcp":
                    sock.connect(addr)
                self._sock, self._addr = sock, addr
                self._backoff = self.retry_initial
                self._next_attempt = 0.0
                return True
            except OSError as exc:
                last_exc = exc
                if sock is not None:
                    sock.close()
        # Logged once per backoff period, not once per alert.
        logger.warning("SyslogOutput: could not connect to %s:%d — %s (retrying in %.0fs)",
                       self.host, self.port, last_exc, self._backoff)
        self._next_attempt = now + self._backoff
        self._backoff = min(self._backoff * 2, self.retry_max)
        return False

    def _send(self, data: bytes) -> None:
        if not self._connect():
            self.dropped += 1
            return
        try:
            if self.protocol == "tcp":
                # Octet-counting framing (RFC 6587 §3.4.1)
                framed = f"{len(data)} ".encode() + data
                self._sock.sendall(framed)
            else:
                self._sock.sendto(data, self._addr)
            self.sent += 1
        except OSError as exc:
            logger.warning("SyslogOutput send error: %s — reconnecting", exc)
            self._disconnect()
            self.dropped += 1
            self._next_attempt = 0.0  # one immediate reconnect, then backoff
            if self._connect():
                try:
                    if self.protocol == "tcp":
                        self._sock.sendall(f"{len(data)} ".encode() + data)
                    else:
                        self._sock.sendto(data, self._addr)
                    self.sent += 1
                    self.dropped -= 1
                except OSError:
                    self._disconnect()

    def _format(self, alert: Alert) -> str:
        sev_num = _SEVERITY_MAP.get(alert.severity, 6)
        pri = self.facility * 8 + sev_num
        ts = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

        # Structured data
        sd_params = " ".join(
            [
                f'severity="{_sd_escape(alert.severity.value)}"',
                f'type="{_sd_escape(alert.alert_type.value)}"',
                f'src="{_sd_escape(alert.src_ip or "-")}"',
                f'dst="{_sd_escape(alert.dst_ip or "-")}"',
                f'rule="{_sd_escape(alert.rule_id or "-")}"',
                f'mitre="{_sd_escape(alert.mitre_technique or "-")}"',
                f'confidence="{alert.confidence:.2f}"',
            ]
        )
        sd = f"[pynids@0 {sd_params}]"

        message = alert.message.replace("\n", " ")
        return (
            f"<{pri}>1 {ts} {self.hostname} {self.app_name} - - {sd} {message}"
        )
