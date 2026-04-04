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
import socket
import time
from datetime import datetime, timezone
from typing import Optional

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


def _sd_escape(value: str) -> str:
    """Escape SD-PARAM value per RFC 5424 §6.3.3."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


class SyslogOutput(BaseOutput):
    """
    Send alerts to a syslog receiver over UDP or TCP.

    Args:
        host:         Syslog server hostname or IP.
        port:         Syslog server port (default 514).
        protocol:     ``'udp'`` (default) or ``'tcp'``.
        facility:     RFC 5424 facility code (default 4 = security).
        app_name:     APPNAME field in syslog header (default ``'pynids'``).
        hostname:     HOSTNAME field (default: local hostname).
        min_severity: Only emit alerts at or above this severity.
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
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.facility = facility
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()
        self.min_severity = min_severity
        self._sock: Optional[socket.socket] = None
        self._connect()

    def emit(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        msg = self._format(alert)
        self._send(msg.encode("utf-8", errors="replace"))

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        try:
            if self.protocol == "tcp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.connect((self.host, self.port))
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            logger.warning("SyslogOutput: could not connect to %s:%d — %s", self.host, self.port, exc)
            self._sock = None

    def _send(self, data: bytes) -> None:
        if self._sock is None:
            return
        try:
            if self.protocol == "tcp":
                # Octet-counting framing (RFC 6587 §3.4.1)
                framed = f"{len(data)} ".encode() + data
                self._sock.sendall(framed)
            else:
                self._sock.sendto(data, (self.host, self.port))
        except OSError as exc:
            logger.warning("SyslogOutput send error: %s — reconnecting", exc)
            self.close()
            self._connect()

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
