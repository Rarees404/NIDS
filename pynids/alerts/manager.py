"""
Alert management: deduplication, suppression, correlation, and dispatch.

AlertManager is the central hub that all alerts flow through before being
sent to one or more output backends.  It provides:

Deduplication
    Identical alerts (same rule, same source, same destination) within a
    configurable time window are collapsed into a single emitted event.
    A ``duplicate_count`` field is added to the evidence of the original.

Suppression
    A whitelist of (rule_id, src_cidr) pairs can be configured.  Any
    alert matching an entry in the whitelist is silently dropped.

Correlation
    When multiple distinct alerts originate from the same source IP
    within a short window, an additional composite ``CORRELATION`` alert
    is emitted, signalling coordinated or multi-vector activity.

Dispatch
    Registered :class:`BaseOutput` backends receive every non-suppressed,
    non-deduplicated alert.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from .model import Alert, AlertType, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output backend base
# ---------------------------------------------------------------------------

class BaseOutput:
    """Abstract base for alert output backends."""

    def emit(self, alert: Alert) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Suppression entry
# ---------------------------------------------------------------------------

class _SuppressionEntry:
    def __init__(self, rule_id: str, src_cidr: str) -> None:
        self.rule_id = rule_id  # "*" means any rule
        try:
            self.network: Optional[Any] = ipaddress.ip_network(src_cidr, strict=False)
        except ValueError:
            self.network = None

    def matches(self, alert: Alert) -> bool:
        if self.rule_id != "*" and self.rule_id != alert.rule_id:
            return False
        if alert.src_ip and self.network is not None:
            try:
                return ipaddress.ip_address(alert.src_ip) in self.network
            except ValueError:
                return False
        return False


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Central alert processing hub.

    Args:
        dedup_window:         Seconds within which identical alerts are collapsed.
        correlation_window:   Seconds used to group alerts for correlation analysis.
        correlation_threshold: Minimum distinct rule IDs from one source before a
                              correlation alert is emitted.
        min_severity:         Drop alerts below this severity level.
        suppression_rules:    List of ``{rule_id, src_cidr}`` suppression entries.
    """

    def __init__(
        self,
        dedup_window: float = 60.0,
        correlation_window: float = 120.0,
        correlation_threshold: int = 3,
        min_severity: Severity = Severity.LOW,
        suppression_rules: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        self.dedup_window = dedup_window
        self.correlation_window = correlation_window
        self.correlation_threshold = correlation_threshold
        self.min_severity = min_severity

        self._outputs: List[BaseOutput] = []
        self._suppression: List[_SuppressionEntry] = [
            _SuppressionEntry(r.get("rule_id", "*"), r.get("src_cidr", "0.0.0.0/0"))
            for r in (suppression_rules or [])
        ]

        # Dedup: {dedup_key → (last_seen_ts, count)}
        self._dedup: Dict[str, Tuple[float, int]] = {}

        # Correlation: {src_ip → deque[(timestamp, rule_id)]}
        self._corr_window: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._corr_alerted: Dict[str, float] = {}  # src_ip → last correlation alert ts

        # Statistics
        self.total_seen: int = 0
        self.total_suppressed: int = 0
        self.total_deduplicated: int = 0
        self.total_emitted: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_output(self, output: BaseOutput) -> None:
        """Register a backend that will receive every emitted alert."""
        self._outputs.append(output)

    def add(self, alert: Alert) -> bool:
        """
        Process *alert* through the dedup/suppression/correlation pipeline.

        Returns True if the alert was emitted to outputs, False if it was
        suppressed or deduplicated.
        """
        self.total_seen += 1

        # Severity gate
        if alert.severity < self.min_severity:
            self.total_suppressed += 1
            return False

        # Suppression whitelist
        if any(e.matches(alert) for e in self._suppression):
            logger.debug("Suppressed alert %s (whitelist)", alert.alert_id)
            self.total_suppressed += 1
            return False

        # Deduplication
        key = alert.dedup_key
        now = time.time()
        if key in self._dedup:
            last_ts, count = self._dedup[key]
            if (now - last_ts) < self.dedup_window:
                self._dedup[key] = (last_ts, count + 1)
                self.total_deduplicated += 1
                logger.debug("Deduplicated alert %s (count=%d)", key, count + 1)
                return False

        self._dedup[key] = (now, 1)
        self._emit(alert)

        # Correlation bookkeeping
        if alert.src_ip:
            self._update_correlation(alert)

        return True

    def close(self) -> None:
        """Flush and close all registered outputs."""
        for output in self._outputs:
            try:
                output.close()
            except Exception as exc:
                logger.error("Error closing output %s: %s", type(output).__name__, exc)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "total_seen": self.total_seen,
            "total_suppressed": self.total_suppressed,
            "total_deduplicated": self.total_deduplicated,
            "total_emitted": self.total_emitted,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _emit(self, alert: Alert) -> None:
        self.total_emitted += 1
        for output in self._outputs:
            try:
                output.emit(alert)
            except Exception as exc:
                logger.error(
                    "Output %s failed to emit alert: %s",
                    type(output).__name__,
                    exc,
                )

    def _update_correlation(self, alert: Alert) -> None:
        """Track alerts per source and emit a correlation alert if warranted."""
        src = alert.src_ip
        now = alert.timestamp
        window = self._corr_window[src]

        # Expire old entries
        while window and (now - window[0][0]) > self.correlation_window:
            window.popleft()

        window.append((now, alert.rule_id or alert.alert_type.value))

        # Count distinct rule IDs in the window
        distinct_rules = {entry[1] for entry in window}
        if len(distinct_rules) < self.correlation_threshold:
            return

        # Suppress duplicate correlation alerts within the same window
        last_corr = self._corr_alerted.get(src, 0.0)
        if (now - last_corr) < self.correlation_window:
            return

        self._corr_alerted[src] = now
        corr_alert = Alert(
            alert_type=AlertType.CORRELATION,
            severity=Severity.CRITICAL,
            message=(
                f"Multi-vector attack from {src}: "
                f"{len(distinct_rules)} distinct detection signatures "
                f"in {self.correlation_window:.0f}s"
            ),
            src_ip=src,
            mitre_technique="T1036",
            tags=["correlation", "multi_vector", "coordinated_attack"],
            confidence=min(1.0, len(distinct_rules) / (self.correlation_threshold * 2)),
            evidence={
                "distinct_signatures": sorted(distinct_rules),
                "event_count": len(window),
                "window_seconds": self.correlation_window,
            },
        )
        self._emit(corr_alert)
