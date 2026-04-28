"""
PyNIDS Detection Engine.

The engine is the central processing pipeline that wires together all
detection subsystems.  Every packet flows through exactly this sequence:

1. **Protocol dissection** — raw bytes → structured layer-7 fields
2. **Flow tracking** — update the stateful connection table
3. **Threat intelligence** — check src/dst IPs and DNS query names
4. **Detectors** — run each registered detector in order
5. **Alert management** — dedup, suppress, correlate, and dispatch

The engine is deliberately synchronous and single-threaded so that it
can be profiled, tested, and reasoned about without concurrency
complexity.  For high-throughput capture the sniffer layer offloads
packet *parsing* to a separate thread; the engine processes one packet
at a time from a queue.

Hot-reload
----------
Call :meth:`reload_rules` at any time to atomically replace the
signature ruleset.  The engine locks briefly while the new rules are
installed, ensuring no packet is processed against a partially-loaded
ruleset.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .alerts.manager import AlertManager
from .alerts.model import Alert, AlertType, Severity
from .detection.anomaly import AnomalyDetector, PortScanDetector, BruteForceDetector
from .detection.behavioral import (
    DnsTunnelingDetector,
    HttpAttackDetector,
    DataExfiltrationDetector,
    BeaconingDetector,
)
from .detection.signature import SignatureDetector, load_rules
from .detection.stealth import (
    BeaconDetector,
    DnsPrefetchDetector,
    LocalhostProbeDetector,
    QuicHttp3Detector,
    TrackerDetector,
    WebRtcLeakDetector,
    WebSocketDetector,
)
from .flow.tracker import FlowTracker
from .intel.threat_intel import ThreatIntel
from .protocols.dissector import dissect

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Orchestrates the full packet-to-alert pipeline.

    Args:
        config:         Full configuration dictionary (see ``configs/enterprise.yaml``).
        rules_path:     Path to the signature rules YAML file (optional).
        intel:          Pre-configured :class:`~pynids.intel.ThreatIntel` instance.
        alert_manager:  Pre-configured :class:`~pynids.alerts.AlertManager` instance.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        rules_path: Optional[str] = None,
        intel: Optional[ThreatIntel] = None,
        alert_manager: Optional[AlertManager] = None,
    ) -> None:
        self._config = config
        self._rules_path = rules_path
        self._lock = threading.Lock()

        # --- Flow tracker ---
        flow_cfg = config.get("flow", {})
        self._flow_tracker = FlowTracker(
            max_flows=flow_cfg.get("max_flows", 100_000),
            idle_timeout=float(flow_cfg.get("idle_timeout", 300)),
        )

        # --- Threat intelligence ---
        self._intel = intel

        # --- Alert manager ---
        self._alert_manager = alert_manager or AlertManager()

        # --- Detectors (ordered: cheapest / most likely to fire first) ---
        self._detectors: list = []
        self._init_detectors(config, rules_path)

        # Hot-reload state
        self._rules_mtime: float = 0.0
        if rules_path and Path(rules_path).exists():
            self._rules_mtime = Path(rules_path).stat().st_mtime

        # Statistics
        self._packets_processed: int = 0
        self._start_time: float = time.time()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_packet(self, meta: Dict[str, Any]) -> List[Alert]:
        """
        Run *meta* through the full detection pipeline.

        Returns the list of alerts raised (may be empty).  Alerts have
        already been sent to the alert manager (and thus to all
        registered output backends); the return value is provided for
        callers that want to inspect or test results directly.
        """
        alerts: List[Alert] = []

        with self._lock:
            self._packets_processed += 1

            # 1. Protocol dissection
            layer7 = dissect(meta)

            # 2. Flow tracking
            flow = self._flow_tracker.update(meta)

            # 3. Threat intelligence checks
            ti_alerts = self._run_threat_intel(meta, layer7)
            alerts.extend(ti_alerts)

            # 4. Run all detectors
            for detector in self._detectors:
                try:
                    for alert in detector.analyze(meta, layer7, flow):
                        alerts.append(alert)
                except Exception as exc:
                    logger.error("Detector %s raised: %s", detector.name, exc)

        # 5. Feed through alert manager (dedup / suppress / correlate)
        for alert in alerts:
            self._alert_manager.add(alert)

        return alerts

    def reload_rules(self) -> bool:
        """
        Hot-reload signature rules from disk.

        Returns True if rules were actually reloaded, False if the file
        has not changed since the last load.
        """
        if not self._rules_path:
            return False
        path = Path(self._rules_path)
        if not path.exists():
            logger.warning("Rules file not found: %s", self._rules_path)
            return False
        mtime = path.stat().st_mtime
        if mtime == self._rules_mtime:
            return False

        new_rules = load_rules(self._rules_path)
        with self._lock:
            for detector in self._detectors:
                if isinstance(detector, SignatureDetector):
                    detector.update_rules(new_rules)
                    self._rules_mtime = mtime
                    logger.info(
                        "Hot-reloaded %d signature rules from %s",
                        len(new_rules),
                        self._rules_path,
                    )
                    return True
        return False

    @property
    def stats(self) -> Dict[str, Any]:
        """Runtime statistics snapshot."""
        uptime = time.time() - self._start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "packets_processed": self._packets_processed,
            "packets_per_second": round(self._packets_processed / max(uptime, 1), 1),
            "active_flows": self._flow_tracker.active_count,
            "alert_stats": self._alert_manager.stats,
        }

    @property
    def alert_manager(self) -> AlertManager:
        return self._alert_manager

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_detectors(
        self, config: Dict[str, Any], rules_path: Optional[str]
    ) -> None:
        """Instantiate and register all configured detectors."""

        # Signature detector
        if rules_path and Path(rules_path).exists():
            rules = load_rules(rules_path)
            self._detectors.append(SignatureDetector(rules))
            logger.info("Loaded %d signature rules from %s", len(rules), rules_path)
        else:
            self._detectors.append(SignatureDetector([]))

        # Anomaly detectors
        anom_cfg = config.get("anomaly", {})
        self._detectors.append(
            AnomalyDetector(
                ewma_alpha=float(anom_cfg.get("ewma_alpha", 0.3)),
                sigma_threshold=float(anom_cfg.get("sigma_threshold", 4.0)),
                window_seconds=int(anom_cfg.get("window_seconds", 10)),
            )
        )

        scan_cfg = config.get("scan", {})
        self._detectors.append(
            PortScanDetector(
                horizontal_threshold=int(scan_cfg.get("horizontal_threshold", 20)),
                horizontal_window=float(scan_cfg.get("horizontal_window", 60)),
                vertical_threshold=int(scan_cfg.get("vertical_threshold", 15)),
                vertical_window=float(scan_cfg.get("vertical_window", 60)),
            )
        )

        bf_cfg = config.get("brute_force", {})
        bf_ports = frozenset(int(p) for p in bf_cfg.get("ports", []))
        self._detectors.append(
            BruteForceDetector(
                threshold=int(bf_cfg.get("threshold", 10)),
                window=float(bf_cfg.get("window", 30)),
                watched_ports=bf_ports or None,
            )
        )

        # Behavioral detectors
        beh_cfg = config.get("behavioral", {})
        self._detectors.append(
            DnsTunnelingDetector(
                entropy_threshold=float(beh_cfg.get("dns_entropy_threshold", 3.5)),
                length_threshold=int(beh_cfg.get("dns_length_threshold", 50)),
            )
        )
        self._detectors.append(HttpAttackDetector())
        self._detectors.append(
            DataExfiltrationDetector(
                threshold_bytes=int(beh_cfg.get("exfil_threshold_bytes", 10 * 1024 * 1024))
            )
        )
        self._detectors.append(
            BeaconingDetector(
                min_connections=int(beh_cfg.get("beacon_min_connections", 6)),
                cv_threshold=float(beh_cfg.get("beacon_cv_threshold", 0.20)),
            )
        )

        # Stealth-activity detectors — surface what browsers hide from
        # the DevTools Network tab (WebRTC IP leaks, localhost probes,
        # QUIC/HTTP3, WebSockets, beacons, prefetch storms, trackers).
        # Enabled by default; disable with `stealth: { enabled: false }`.
        stealth_cfg = config.get("stealth", {}) or {}
        if stealth_cfg.get("enabled", True):
            self._detectors.append(WebRtcLeakDetector())
            self._detectors.append(
                LocalhostProbeDetector(
                    scan_threshold=int(stealth_cfg.get("scan_threshold", 5)),
                    scan_window=float(stealth_cfg.get("scan_window", 30.0)),
                )
            )
            self._detectors.append(QuicHttp3Detector())
            self._detectors.append(WebSocketDetector())
            self._detectors.append(BeaconDetector())
            self._detectors.append(
                DnsPrefetchDetector(
                    burst_threshold=int(stealth_cfg.get("dns_prefetch_threshold", 8)),
                    window_seconds=float(stealth_cfg.get("dns_prefetch_window", 5.0)),
                )
            )
            if stealth_cfg.get("trackers_enabled", True):
                self._detectors.append(TrackerDetector())

        logger.info("Initialised %d detectors", len(self._detectors))

    def _run_threat_intel(
        self, meta: Dict[str, Any], layer7: Dict[str, Any]
    ) -> List[Alert]:
        if not self._intel:
            return []

        alerts: List[Alert] = []

        # Check source IP
        src_ip = meta.get("src_ip")
        if src_ip:
            entry = self._intel.check_ip(src_ip)
            if entry:
                alerts.append(
                    Alert(
                        alert_type=AlertType.THREAT_INTEL,
                        severity=Severity(entry.severity),
                        message=(
                            f"Traffic from known malicious IP {src_ip} "
                            f"({entry.category}): {entry.description}"
                        ),
                        src_ip=src_ip,
                        dst_ip=meta.get("dst_ip"),
                        dst_port=meta.get("dst_port"),
                        protocol=meta.get("protocol"),
                        mitre_technique="T1071",
                        tags=["threat_intel", entry.category],
                        confidence=1.0,
                        evidence={
                            "matched_indicator": entry.indicator,
                            "category": entry.category,
                        },
                    )
                )

        # Check destination IP
        dst_ip = meta.get("dst_ip")
        if dst_ip:
            entry = self._intel.check_ip(dst_ip)
            if entry:
                alerts.append(
                    Alert(
                        alert_type=AlertType.THREAT_INTEL,
                        severity=Severity(entry.severity),
                        message=(
                            f"Connection to known malicious IP {dst_ip} "
                            f"({entry.category}): {entry.description}"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=meta.get("dst_port"),
                        protocol=meta.get("protocol"),
                        mitre_technique="T1071",
                        tags=["threat_intel", entry.category],
                        confidence=1.0,
                        evidence={
                            "matched_indicator": entry.indicator,
                            "category": entry.category,
                        },
                    )
                )

        # Check DNS query names
        dns_name = layer7.get("dns", {}).get("query_name")
        if dns_name:
            entry = self._intel.check_domain(dns_name)
            if entry:
                alerts.append(
                    Alert(
                        alert_type=AlertType.THREAT_INTEL,
                        severity=Severity(entry.severity),
                        message=(
                            f"DNS query for known malicious domain '{dns_name}' "
                            f"({entry.category}): {entry.description}"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=meta.get("dst_port"),
                        protocol=meta.get("protocol"),
                        mitre_technique="T1071.004",
                        tags=["threat_intel", "dns", entry.category],
                        confidence=1.0,
                        evidence={
                            "query_name": dns_name,
                            "matched_indicator": entry.indicator,
                            "category": entry.category,
                        },
                    )
                )

        return alerts
