"""
Statistical and heuristic anomaly detection for PyNIDS.

This module provides three complementary detectors that share a common
:class:`BaseDetector` interface:

AnomalyDetector
    Volumetric spike detection using Exponentially Weighted Moving Average
    (EWMA) with adaptive standard-deviation thresholding.  Detects sudden
    bursts of traffic from a single source that deviate significantly from
    that source's historical baseline.

PortScanDetector
    Stateful port-scan and host-discovery detection.

    - **Horizontal scan** (host sweep): one source scanning many hosts on
      the same port within a time window.  Indicates network reconnaissance.
      MITRE: T1046.
    - **Vertical scan** (port scan): one source probing many ports on a
      single target.  Classic TCP/SYN port scan pattern.  MITRE: T1046.

BruteForceDetector
    Brute-force / credential-stuffing detection.  Counts connection
    attempts from one source to a single service (e.g. SSH on port 22)
    and fires when the rate exceeds a configurable threshold.  MITRE: T1110.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Volumetric spike detection
# ---------------------------------------------------------------------------

@dataclass
class _RateStats:
    ewma_rate: float = 0.0
    counts_window: Deque[Tuple[float, int]] = field(default_factory=lambda: deque(maxlen=60))


class AnomalyDetector(BaseDetector):
    """
    Per-source EWMA volumetric anomaly detector.

    For each observed source IP the detector maintains a sliding-window
    count and an EWMA of recent packet rates.  When the current window
    rate exceeds ``ewma ± sigma * stddev`` an alert is raised.

    Args:
        ewma_alpha:       Smoothing factor α ∈ (0, 1].  Higher = faster adaptation.
        sigma_threshold:  How many standard deviations above the mean triggers an alert.
        window_seconds:   Width of each counting window in seconds.
    """

    def __init__(
        self,
        ewma_alpha: float = 0.3,
        sigma_threshold: float = 4.0,
        window_seconds: int = 10,
    ) -> None:
        self.ewma_alpha = ewma_alpha
        self.sigma_threshold = sigma_threshold
        self.window_seconds = window_seconds
        self._per_source: Dict[str, _RateStats] = defaultdict(_RateStats)

    @property
    def name(self) -> str:
        return "anomaly_volumetric"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        src_ip = meta.get("src_ip")
        if not src_ip:
            return
        ts = meta.get("timestamp", time.time())
        yield from self._observe(src_ip, ts)

    def _observe(self, src_ip: str, ts: float) -> Iterable[Alert]:
        stats = self._per_source[src_ip]
        wkey = ts - (ts % self.window_seconds)

        if not stats.counts_window or stats.counts_window[-1][0] != wkey:
            stats.counts_window.append((wkey, 1))
        else:
            w, c = stats.counts_window[-1]
            stats.counts_window[-1] = (w, c + 1)

        current_count = stats.counts_window[-1][1]
        current_rate = current_count / float(self.window_seconds)

        if stats.ewma_rate == 0.0:
            stats.ewma_rate = current_rate
        else:
            stats.ewma_rate = (
                self.ewma_alpha * current_rate + (1 - self.ewma_alpha) * stats.ewma_rate
            )

        rates = [c / float(self.window_seconds) for _, c in stats.counts_window]
        if len(rates) >= 3:
            mean = sum(rates) / len(rates)
            variance = sum((r - mean) ** 2 for r in rates) / (len(rates) - 1)
            stddev = variance ** 0.5
        else:
            stddev = 0.0

        threshold = stats.ewma_rate + self.sigma_threshold * stddev

        if stddev > 0 and current_rate > threshold and current_count > 5:
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(
                    f"Traffic spike from {src_ip}: "
                    f"{current_rate:.1f} pkt/s (threshold {threshold:.1f} pkt/s)"
                ),
                src_ip=src_ip,
                mitre_technique="T1498",
                tags=["volumetric", "anomaly", "dos"],
                confidence=min(1.0, (current_rate - threshold) / threshold),
                evidence={
                    "current_rate_pps": current_rate,
                    "threshold_pps": threshold,
                    "ewma_rate": stats.ewma_rate,
                    "stddev": stddev,
                    "window_start": wkey,
                },
            )


# ---------------------------------------------------------------------------
# Port scan detection
# ---------------------------------------------------------------------------

@dataclass
class _ScanState:
    """Per-source scan tracking state."""
    # Horizontal: {dst_port → set of dst_ips}
    horiz: Dict[int, Set[str]] = field(default_factory=dict)
    horiz_first_seen: Dict[int, float] = field(default_factory=dict)
    # Vertical: {dst_ip → set of dst_ports}
    vert: Dict[str, Set[int]] = field(default_factory=dict)
    vert_first_seen: Dict[str, float] = field(default_factory=dict)
    # Track which alerts have already fired to avoid floods
    horiz_alerted: Set[int] = field(default_factory=set)
    vert_alerted: Set[str] = field(default_factory=set)


class PortScanDetector(BaseDetector):
    """
    Detect horizontal (host-sweep) and vertical (port-scan) scan activity.

    Args:
        horizontal_threshold: Unique destination IPs on the same port before alert.
        horizontal_window:    Observation window in seconds for horizontal scans.
        vertical_threshold:   Unique destination ports on the same host before alert.
        vertical_window:      Observation window in seconds for vertical scans.
    """

    def __init__(
        self,
        horizontal_threshold: int = 20,
        horizontal_window: float = 60.0,
        vertical_threshold: int = 15,
        vertical_window: float = 60.0,
    ) -> None:
        self.horizontal_threshold = horizontal_threshold
        self.horizontal_window = horizontal_window
        self.vertical_threshold = vertical_threshold
        self.vertical_window = vertical_window
        self._state: Dict[str, _ScanState] = defaultdict(_ScanState)

    @property
    def name(self) -> str:
        return "port_scan"

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
        state = self._state[src_ip]

        yield from self._check_horizontal(src_ip, dst_ip, dst_port, ts, state)
        yield from self._check_vertical(src_ip, dst_ip, dst_port, ts, state)

    def _check_horizontal(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        ts: float,
        state: _ScanState,
    ) -> Iterable[Alert]:
        """One source → many destinations on the same port."""
        if dst_port not in state.horiz:
            state.horiz[dst_port] = set()
            state.horiz_first_seen[dst_port] = ts

        elapsed = ts - state.horiz_first_seen[dst_port]
        if elapsed > self.horizontal_window:
            # Reset window
            state.horiz[dst_port] = set()
            state.horiz_first_seen[dst_port] = ts
            state.horiz_alerted.discard(dst_port)

        state.horiz[dst_port].add(dst_ip)
        unique_hosts = len(state.horiz[dst_port])

        if unique_hosts >= self.horizontal_threshold and dst_port not in state.horiz_alerted:
            state.horiz_alerted.add(dst_port)
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(
                    f"Host sweep from {src_ip}: {unique_hosts} hosts "
                    f"on port {dst_port} in {elapsed:.0f}s"
                ),
                src_ip=src_ip,
                dst_port=dst_port,
                mitre_technique="T1046",
                tags=["recon", "host_sweep", "portscan"],
                confidence=min(1.0, unique_hosts / (self.horizontal_threshold * 2)),
                evidence={
                    "unique_hosts_scanned": unique_hosts,
                    "target_port": dst_port,
                    "window_seconds": elapsed,
                    "sample_targets": list(state.horiz[dst_port])[:10],
                },
            )

    def _check_vertical(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        ts: float,
        state: _ScanState,
    ) -> Iterable[Alert]:
        """One source probing many ports on the same destination."""
        if dst_ip not in state.vert:
            state.vert[dst_ip] = set()
            state.vert_first_seen[dst_ip] = ts

        elapsed = ts - state.vert_first_seen[dst_ip]
        if elapsed > self.vertical_window:
            state.vert[dst_ip] = set()
            state.vert_first_seen[dst_ip] = ts
            state.vert_alerted.discard(dst_ip)

        state.vert[dst_ip].add(dst_port)
        unique_ports = len(state.vert[dst_ip])

        if unique_ports >= self.vertical_threshold and dst_ip not in state.vert_alerted:
            state.vert_alerted.add(dst_ip)
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(
                    f"Port scan from {src_ip} → {dst_ip}: "
                    f"{unique_ports} ports in {elapsed:.0f}s"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                mitre_technique="T1046",
                tags=["recon", "portscan", "vertical_scan"],
                confidence=min(1.0, unique_ports / (self.vertical_threshold * 2)),
                evidence={
                    "unique_ports_scanned": unique_ports,
                    "target_host": dst_ip,
                    "window_seconds": elapsed,
                    "sample_ports": sorted(state.vert[dst_ip])[:20],
                },
            )


# ---------------------------------------------------------------------------
# Brute-force detection
# ---------------------------------------------------------------------------

class BruteForceDetector(BaseDetector):
    """
    Detect credential-brute-force attempts against network services.

    Tracks connection attempts from each source IP to each (dst_ip, dst_port)
    service pair.  When the attempt count exceeds *threshold* within
    *window* seconds, a HIGH-severity alert is raised.

    Args:
        threshold:    Number of attempts that triggers an alert.
        window:       Sliding window duration in seconds.
        watched_ports: Set of ports considered authentication services.
    """

    _DEFAULT_PORTS = frozenset({21, 22, 23, 25, 110, 143, 389, 636, 3389, 5900, 8080})

    def __init__(
        self,
        threshold: int = 10,
        window: float = 30.0,
        watched_ports: Optional[frozenset] = None,
    ) -> None:
        self.threshold = threshold
        self.window = window
        self.watched_ports = watched_ports if watched_ports is not None else self._DEFAULT_PORTS
        # {(src_ip, dst_ip, dst_port) → deque[timestamps]}
        self._attempts: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(deque)
        # Track fired alerts to suppress duplicates within the window
        self._alerted: Set[Tuple[str, str, int]] = set()

    @property
    def name(self) -> str:
        return "brute_force"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dst_port = meta.get("dst_port")
        if dst_port not in self.watched_ports:
            return

        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")
        if not (src_ip and dst_ip):
            return

        ts = meta.get("timestamp", time.time())
        key: Tuple[str, str, int] = (src_ip, dst_ip, dst_port)
        bucket = self._attempts[key]

        # Expire old entries
        while bucket and (ts - bucket[0]) > self.window:
            bucket.popleft()

        bucket.append(ts)
        count = len(bucket)

        if count >= self.threshold and key not in self._alerted:
            self._alerted.add(key)
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(
                    f"Brute force: {src_ip} → {dst_ip}:{dst_port} "
                    f"({count} attempts in {self.window:.0f}s)"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=meta.get("protocol"),
                mitre_technique="T1110",
                tags=["brute_force", "credential_access"],
                confidence=min(1.0, count / (self.threshold * 2)),
                evidence={
                    "attempt_count": count,
                    "window_seconds": self.window,
                    "service_port": dst_port,
                },
            )
        elif count < self.threshold:
            # Allow re-alerting once the window has slid far enough
            self._alerted.discard(key)
