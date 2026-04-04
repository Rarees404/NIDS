"""
Behavioral / heuristic detection for PyNIDS.

Whereas signature detection requires exact pattern matches and anomaly
detection reacts to statistical outliers, behavioral detection models
*sequences of actions* that collectively indicate malicious intent.

Detectors
---------
DnsTunnelingDetector
    Identifies DNS queries used as covert data-exfiltration channels.
    High Shannon entropy and/or abnormally long subdomain labels are
    characteristic of DNS tunneling tools (iodine, dnscat2, DNScat).
    MITRE: T1071.004.

HttpAttackDetector
    Leverages the HTTP dissector's heuristic flags (SQL injection,
    XSS, path traversal, scanner user-agents) to generate severity-
    graded alerts for web application attacks.
    MITRE: T1190.

DataExfiltrationDetector
    Watches per-flow outbound byte counts.  When a single flow
    transfers an unusually large amount of data to an external host,
    an alert is raised for analyst review.
    MITRE: T1041.

BeaconingDetector
    Identifies C2 beaconing by analysing the regularity of connection
    intervals between the same source/destination pair.  Beaconing
    malware sends periodic check-ins at nearly constant intervals.
    Low coefficient of variation (stddev/mean) over several samples
    indicates automated, machine-generated traffic.
    MITRE: T1071.
"""
from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

class DnsTunnelingDetector(BaseDetector):
    """
    Detect DNS-based covert channels using entropy and label-length analysis.

    Args:
        entropy_threshold: Minimum Shannon entropy (bits) of the query name
                           to be considered suspicious (default 3.5).
        length_threshold:  Minimum total length of a query name before
                           it is considered anomalously long (default 50).
        depth_threshold:   Minimum subdomain depth (label count) indicating
                           a tunneled payload (default 5).
    """

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        depth_threshold: int = 5,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.depth_threshold = depth_threshold

    @property
    def name(self) -> str:
        return "dns_tunneling"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dns = layer7.get("dns")
        if not dns:
            return

        query_name: Optional[str] = dns.get("query_name")
        if not query_name:
            return

        entropy: float = dns.get("name_entropy", 0.0)
        length: int = dns.get("name_length", 0)
        depth: int = dns.get("subdomain_depth", 0)

        triggered_reasons: List[str] = []
        if entropy >= self.entropy_threshold:
            triggered_reasons.append(f"entropy={entropy:.2f}")
        if length >= self.length_threshold:
            triggered_reasons.append(f"length={length}")
        if depth >= self.depth_threshold:
            triggered_reasons.append(f"depth={depth}")

        if not triggered_reasons:
            return

        confidence = min(
            1.0,
            (
                (entropy / self.entropy_threshold if entropy >= self.entropy_threshold else 0)
                + (length / self.length_threshold if length >= self.length_threshold else 0)
            ) / 2.0,
        )

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.HIGH,
            message=(
                f"Possible DNS tunneling from {meta.get('src_ip')}: "
                f"query '{query_name}' ({', '.join(triggered_reasons)})"
            ),
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            mitre_technique="T1071.004",
            tags=["dns_tunneling", "exfiltration", "covert_channel"],
            confidence=confidence,
            evidence={
                "query_name": query_name,
                "entropy": entropy,
                "name_length": length,
                "subdomain_depth": depth,
            },
        )


# ---------------------------------------------------------------------------
# HTTP attack patterns
# ---------------------------------------------------------------------------

class HttpAttackDetector(BaseDetector):
    """
    Raise alerts for HTTP-layer attack heuristics detected by the dissector.

    Each heuristic (SQLi, XSS, path traversal, scanner) maps to a
    distinct alert with an appropriate severity level and MITRE reference.
    """

    @property
    def name(self) -> str:
        return "http_attacks"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        http = layer7.get("http")
        if not http:
            return

        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")
        dst_port = meta.get("dst_port")
        uri = http.get("uri", "")

        if http.get("sqli_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.CRITICAL,
                message=f"SQL injection attempt from {src_ip} → {dst_ip}{uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1190",
                tags=["sqli", "webapp", "initial_access"],
                confidence=0.85,
                evidence={"uri": uri, "method": http.get("method"), "host": http.get("host")},
            )

        if http.get("xss_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.HIGH,
                message=f"XSS attempt from {src_ip} → {dst_ip}{uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1059.007",
                tags=["xss", "webapp"],
                confidence=0.80,
                evidence={"uri": uri, "method": http.get("method")},
            )

        if http.get("path_traversal_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.HIGH,
                message=f"Path traversal attempt from {src_ip}: {uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1083",
                tags=["path_traversal", "webapp"],
                confidence=0.80,
                evidence={"uri": uri},
            )

        if http.get("scanner_ua"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.LOW,
                message=(
                    f"Known scanner user-agent from {src_ip}: "
                    f"{http.get('user_agent', '')[:80]}"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1595",
                tags=["scanner", "recon"],
                confidence=0.95,
                evidence={
                    "user_agent": http.get("user_agent"),
                    "uri": uri,
                    "method": http.get("method"),
                },
            )


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

class DataExfiltrationDetector(BaseDetector):
    """
    Flag flows that transfer an unusually large volume of data outbound.

    Uses the :class:`~pynids.flow.tracker.Flow` byte counter to identify
    flows that have already transferred more than *threshold_bytes*.

    Args:
        threshold_bytes: Outbound byte count that triggers an alert (default 10 MiB).
    """

    _DEFAULT_THRESHOLD = 10 * 1024 * 1024  # 10 MiB

    def __init__(self, threshold_bytes: int = _DEFAULT_THRESHOLD) -> None:
        self.threshold_bytes = threshold_bytes
        self._alerted_flows: set = set()

    @property
    def name(self) -> str:
        return "data_exfiltration"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        if flow is None:
            return

        if flow.byte_count < self.threshold_bytes:
            return
        if flow.flow_id in self._alerted_flows:
            return

        self._alerted_flows.add(flow.flow_id)
        mb = flow.byte_count / (1024 * 1024)

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.HIGH,
            message=(
                f"Possible data exfiltration: {flow.src_ip} → {flow.dst_ip}:{flow.dst_port} "
                f"transferred {mb:.1f} MiB"
            ),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            flow_id=flow.flow_id,
            mitre_technique="T1041",
            tags=["exfiltration", "data_transfer"],
            confidence=0.70,
            evidence={
                "bytes_transferred": flow.byte_count,
                "megabytes": round(mb, 2),
                "packet_count": flow.packet_count,
                "duration_seconds": round(flow.duration, 2),
                "avg_packet_size_bytes": round(flow.avg_packet_size, 2),
            },
        )


# ---------------------------------------------------------------------------
# C2 beaconing
# ---------------------------------------------------------------------------

class BeaconingDetector(BaseDetector):
    """
    Identify C2 beaconing via inter-arrival time regularity analysis.

    For each (src_ip, dst_ip, dst_port) tuple, the detector records the
    timestamps of connection events.  Once a minimum number of samples
    is collected, the coefficient of variation (CV = stddev/mean) of the
    inter-arrival intervals is computed.  A very low CV indicates highly
    regular, automated traffic consistent with beaconing malware.

    Args:
        min_connections:         Minimum events before analysis is performed.
        cv_threshold:            CV below this value triggers an alert (default 0.2).
        max_interval_seconds:    Ignore intervals longer than this (connection gaps).
    """

    def __init__(
        self,
        min_connections: int = 6,
        cv_threshold: float = 0.20,
        max_interval_seconds: float = 3600.0,
    ) -> None:
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.max_interval_seconds = max_interval_seconds
        # {(src_ip, dst_ip, dst_port) → deque[timestamps]}
        self._history: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(
            lambda: deque(maxlen=30)
        )
        self._alerted: set = set()

    @property
    def name(self) -> str:
        return "beaconing"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")
        dst_port = meta.get("dst_port")
        if not (src_ip and dst_ip and dst_port is not None):
            return

        ts = meta.get("timestamp", time.time())
        key: Tuple[str, str, int] = (src_ip, dst_ip, dst_port)
        hist = self._history[key]
        hist.append(ts)

        if len(hist) < self.min_connections:
            return
        if key in self._alerted:
            return

        intervals = [
            hist[i] - hist[i - 1]
            for i in range(1, len(hist))
            if (hist[i] - hist[i - 1]) <= self.max_interval_seconds
        ]
        if len(intervals) < self.min_connections - 1:
            return

        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cv = stddev / mean

        if cv <= self.cv_threshold:
            self._alerted.add(key)
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.HIGH,
                message=(
                    f"C2 beaconing suspected: {src_ip} → {dst_ip}:{dst_port} "
                    f"interval={mean:.1f}s CV={cv:.3f}"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=meta.get("protocol"),
                mitre_technique="T1071",
                tags=["beaconing", "c2", "persistence"],
                confidence=max(0.0, 1.0 - cv / self.cv_threshold),
                evidence={
                    "mean_interval_seconds": round(mean, 2),
                    "stddev_seconds": round(stddev, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "sample_count": len(hist),
                },
            )
