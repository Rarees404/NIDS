"""
Alert management: deduplication, suppression, correlation, and dispatch.

AlertManager is the central hub that all alerts flow through before being
sent to one or more output backends.  It provides:

Deduplication
    Identical alerts (same rule, same source, same destination) within a
    configurable time window are collapsed into a single emitted event.
    A ``duplicate_count`` field (duplicates collapsed so far) is kept up to
    date in the evidence of the original, in-memory alert.

Suppression
    A whitelist of (rule_id, src_cidr) pairs can be configured.  Any
    alert matching an entry in the whitelist is silently dropped.  An
    omitted or ``"*"`` src_cidr matches any source (IPv4 and IPv6).

Correlation
    When multiple distinct alerts originate from the same source IP
    within a short window, an additional composite ``CORRELATION`` alert
    is emitted, signalling coordinated or multi-vector activity.

Dispatch
    Registered :class:`BaseOutput` backends receive every non-suppressed,
    non-deduplicated alert.  Outputs run outside the manager's lock so a
    slow backend only delays its own caller, never other capture threads.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from .mitre import technique as _mitre
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
    def __init__(self, rule_id: str, src_cidr: Optional[str]) -> None:
        self.rule_id = rule_id  # "*" means any rule
        # None = any source, of either address family.
        self.network: Optional[Any] = None
        if src_cidr not in (None, "", "*"):
            self.network = ipaddress.ip_network(str(src_cidr).strip(), strict=False)

    def matches(self, alert: Alert) -> bool:
        if self.rule_id != "*" and self.rule_id != alert.rule_id:
            return False
        if self.network is None:
            return True
        if not alert.src_ip:
            return False
        try:
            addr = ipaddress.ip_address(alert.src_ip)
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped is not None and self.network.version == 4:
            addr = addr.ipv4_mapped
        return addr.version == self.network.version and addr in self.network


def _build_suppression(rules: Optional[List[Dict[str, str]]]) -> List[_SuppressionEntry]:
    entries: List[_SuppressionEntry] = []
    for r in rules or []:
        try:
            entries.append(_SuppressionEntry(str(r.get("rule_id", "*")), r.get("src_cidr")))
        except (ValueError, TypeError) as exc:
            logger.warning("Ignoring suppression rule %r: invalid src_cidr (%s)", r, exc)
    return entries


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
        # Callables returning True drop an alert (e.g. the user's allowlist).
        self._filters: List[Callable[[Alert], bool]] = []
        self._suppression: List[_SuppressionEntry] = _build_suppression(suppression_rules)

        # Dedup: {dedup_key → (first_seen_ts, count, original alert)}
        self._dedup: Dict[str, Tuple[float, int, Alert]] = {}

        # Correlation: {src_ip → deque[(timestamp, rule_id, severity, technique, message)]}
        self._corr_window: Dict[str, Deque[Tuple[Any, ...]]] = defaultdict(deque)
        self._corr_alerted: Dict[str, float] = {}  # src_ip → last correlation alert ts
        self._last_prune: float = time.time()

        # Alerts arrive from several threads (one capture thread per
        # interface, the LAN inventory, the C2 correlator).  The lock guards
        # the bookkeeping only; outputs are called after it is released, so
        # an output may add an alert of its own while being emitted.
        self._lock = threading.RLock()

        # Statistics
        self.total_seen: int = 0
        self.total_suppressed: int = 0
        self.total_deduplicated: int = 0
        self.total_emitted: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_filter(self, predicate: Callable[[Alert], bool]) -> None:
        """Drop every alert for which *predicate* returns True."""
        self._filters.append(predicate)

    def register_output(self, output: BaseOutput) -> None:
        """Register a backend that will receive every emitted alert."""
        self._outputs.append(output)

    def add(self, alert: Alert) -> bool:
        """
        Process *alert* through the dedup/suppression/correlation pipeline.

        Returns True if the alert was emitted to outputs, False if it was
        suppressed or deduplicated.
        """
        with self._lock:
            to_emit = self._add(alert)
        for out in to_emit:
            self._emit(out)
        return bool(to_emit)

    def _add(self, alert: Alert) -> List[Alert]:
        """Bookkeeping under the lock; returns the alerts to hand to outputs."""
        self.total_seen += 1

        # Severity gate
        if alert.severity < self.min_severity:
            self.total_suppressed += 1
            return []

        # Suppression whitelist
        if any(e.matches(alert) for e in self._suppression):
            logger.debug("Suppressed alert %s (whitelist)", alert.alert_id)
            self.total_suppressed += 1
            return []
        for predicate in self._filters:
            try:
                dropped = predicate(alert)
            except Exception as exc:  # noqa: BLE001 — a broken filter must not lose alerts
                logger.error("Alert filter failed: %s", exc)
                dropped = False
            if dropped:
                self.total_suppressed += 1
                return []

        # Deduplication
        key = alert.dedup_key
        now = time.time()
        if now - self._last_prune >= 60.0:
            self._prune(now)
        if key in self._dedup:
            first_ts, count, original = self._dedup[key]
            if (now - first_ts) < self.dedup_window:
                self._dedup[key] = (first_ts, count + 1, original)
                # Swap in a new dict: outputs (outside the lock) may be iterating the old one.
                original.evidence = {**original.evidence, "duplicate_count": count}
                self.total_deduplicated += 1
                logger.debug("Deduplicated alert %s (count=%d)", key, count + 1)
                return []

        self._dedup[key] = (now, 1, alert)
        self.total_emitted += 1
        to_emit = [alert]

        # Correlation bookkeeping.  X-Ray privacy telemetry (STEALTH-*) is
        # excluded: it describes this machine's own browsing (trackers, QUIC,
        # DoH …) and would otherwise brand the local host a "multi-vector
        # attacker" several times an hour.
        if alert.src_ip and self._correlates(alert):
            corr = self._update_correlation(alert)
            if corr is not None:
                self.total_emitted += 1
                to_emit.append(corr)

        return to_emit

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

    def _prune(self, now: float) -> None:
        """Forget dedup / correlation state that has aged out (bounds memory)."""
        self._last_prune = now
        self._dedup = {k: v for k, v in self._dedup.items() if now - v[0] < self.dedup_window}
        for src in [s for s, w in self._corr_window.items()
                    if not w or now - w[-1][0] > self.correlation_window]:
            del self._corr_window[src]
        self._corr_alerted = {s: t for s, t in self._corr_alerted.items()
                              if now - t < self.correlation_window}

    def _emit(self, alert: Alert) -> None:
        for output in list(self._outputs):
            try:
                output.emit(alert)
            except Exception as exc:
                logger.error(
                    "Output %s failed to emit alert: %s",
                    type(output).__name__,
                    exc,
                )

    # Tags of alerts that describe the machine or its hygiene, not an attack step.
    _NON_ATTACK_TAGS = frozenset({"policy", "host_risk", "new_program", "baseline", "new_device"})

    def _correlates(self, alert: Alert) -> bool:
        """
        Does *alert* count as one vector of a multi-vector attack?

        Left out: X-Ray privacy telemetry (STEALTH-*), which describes this
        machine's own browsing; LOW-severity notes; hygiene findings (old TLS,
        default SNMP community); and host baseline events (a new program, a
        new device).  Three of those in two minutes is an ordinary afternoon,
        not a coordinated attack.
        """
        if (alert.rule_id or "").startswith("STEALTH-"):
            return False
        if alert.severity < Severity.MEDIUM or alert.alert_type == AlertType.CORRELATION:
            return False
        return not self._NON_ATTACK_TAGS.intersection(alert.tags or ())

    def _update_correlation(self, alert: Alert) -> Optional[Alert]:
        """Track alerts per source and emit a correlation alert if warranted."""
        src = alert.src_ip
        now = alert.timestamp
        window = self._corr_window[src]

        # Expire old entries
        while window and (now - window[0][0]) > self.correlation_window:
            window.popleft()

        window.append((now, alert.rule_id or alert.alert_type.value, alert.severity.value,
                       alert.mitre_technique, alert.message))

        # Count distinct rule IDs in the window
        distinct_rules = {entry[1] for entry in window}
        if len(distinct_rules) < self.correlation_threshold:
            return None

        # Suppress duplicate correlation alerts within the same window
        last_corr = self._corr_alerted.get(src, 0.0)
        if (now - last_corr) < self.correlation_window:
            return None

        self._corr_alerted[src] = now
        # One line per contributing detection (the latest of each), oldest first,
        # and the ATT&CK tactics they span: the outline of what happened.
        latest: Dict[str, Tuple[Any, ...]] = {}
        for entry in window:
            latest[entry[1]] = entry
        chain = [
            {"time": e[0], "detection": e[1], "severity": e[2], "mitre": e[3], "message": e[4]}
            for e in sorted(latest.values(), key=lambda e: e[0])
        ]
        tactics: List[str] = []
        for e in chain:
            info = _mitre(e["mitre"])
            if info and info.get("tactic") and info["tactic"] not in tactics:
                tactics.append(info["tactic"])
        span = f" spanning {', '.join(tactics)}" if len(tactics) > 1 else ""
        return Alert(
            alert_type=AlertType.CORRELATION,
            severity=Severity.CRITICAL,
            message=(
                f"Multi-vector attack from {src}: "
                f"{len(distinct_rules)} distinct detection signatures "
                f"in {self.correlation_window:.0f}s{span}"
            ),
            src_ip=src,
            mitre_technique="T1036",
            tags=["correlation", "multi_vector", "coordinated_attack"],
            confidence=min(1.0, len(distinct_rules) / (self.correlation_threshold * 2)),
            evidence={
                "distinct_signatures": sorted(distinct_rules),
                "event_count": len(window),
                "window_seconds": self.correlation_window,
                "tactics": tactics,
                "chain": chain,
            },
        )
