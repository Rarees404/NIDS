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
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Sequence, Union

from .alerts.manager import AlertManager
from .alerts.model import Alert, AlertType, Severity
from .detection.anomaly import AnomalyDetector, PortScanDetector, BruteForceDetector
from .detection.base import BaseDetector
from .detection.behavioral import (
    DgaDetector,
    DnsTunnelingDetector,
    HttpAttackDetector,
    DataExfiltrationDetector,
    BeaconingDetector,
)
from .detection.signature import SignatureDetector, load_rules
from .detection.stealth import (
    BeaconDetector,
    DohDetector,
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

if TYPE_CHECKING:
    from .enrich import Enricher

logger = logging.getLogger(__name__)

# The tuned ruleset shipped inside the package (``rules/enterprise_rules.yaml``
# in a source checkout is a link to it).
BUILTIN_RULES = Path(__file__).resolve().parent / "rules" / "default_rules.yaml"


def load_rule_files(paths: Iterable[str]) -> List[Dict[str, Any]]:
    """
    Load several rule files into one ruleset.

    A rule in a later file replaces the rule with the same ``id`` from an
    earlier one, so a small local file can retune or switch off
    (``enabled: false``) individual built-in rules.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    anonymous = 0
    for path in paths:
        if not Path(path).exists():
            logger.debug("Rules file not present: %s", path)
            continue
        try:
            rules = load_rules(path)
        except Exception as exc:  # noqa: BLE001 — a broken file must not stop the others
            logger.error("Could not load rules from %s: %s", path, exc)
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("id")
            if rule_id is None:
                anonymous += 1
                rule_id = f"__anonymous_{anonymous}"
            previous = merged.get(str(rule_id))
            if previous is not None and "match" not in rule and "when" not in rule:
                # A partial override: {id: X, enabled: false} or {id: X, severity: LOW}.
                rule = {**previous, **rule}
            merged[str(rule_id)] = rule
    return list(merged.values())


def _mtimes(paths: Iterable[str]) -> tuple:
    out = []
    for path in paths:
        try:
            out.append(Path(path).stat().st_mtime)
        except OSError:
            out.append(None)
    return tuple(out)


class DetectionEngine:
    """
    Orchestrates the full packet-to-alert pipeline.

    Args:
        config:         Full configuration dictionary (see ``configs/enterprise.yaml``).
        rules_path:     Path to the signature rules YAML file, or a list of files
                        merged in order (later files override rules by id).
        intel:          Pre-configured :class:`~pynids.intel.ThreatIntel` instance.
        alert_manager:  Pre-configured :class:`~pynids.alerts.AlertManager` instance.
        enricher:       Optional :class:`~pynids.enrich.Enricher` that adds app,
                        hostname, and GeoIP context to packets and alerts.
        packet_observers: Callables invoked with ``(meta, layer7, context)`` for
                        every packet (live traffic statistics).
    """

    def __init__(
        self,
        config: Dict[str, Any],
        rules_path: Union[str, Sequence[str], None] = None,
        intel: Optional[ThreatIntel] = None,
        alert_manager: Optional[AlertManager] = None,
        enricher: Optional["Enricher"] = None,
        packet_observers: Optional[List[Callable[[dict, dict, dict], None]]] = None,
    ) -> None:
        self._config = config
        if not rules_path:
            self._rule_paths: List[str] = []
        elif isinstance(rules_path, (str, Path)):
            self._rule_paths = [str(rules_path)]
        else:
            self._rule_paths = [str(p) for p in rules_path if p]
        self._rules_path = self._rule_paths[0] if self._rule_paths else None
        self._lock = threading.Lock()

        # --- Flow tracker ---
        flow_cfg = config.get("flow", {})
        self._flow_tracker = FlowTracker(
            max_flows=flow_cfg.get("max_flows", 100_000),
            idle_timeout=float(flow_cfg.get("idle_timeout", 300)),
            udp_session_gap=float(flow_cfg.get("udp_session_gap", 60)),
        )

        # --- Threat intelligence ---
        self._intel = intel

        # --- Alert manager ---
        self._alert_manager = alert_manager or AlertManager()

        # --- Enrichment + per-packet observers ---
        self._enricher = enricher
        self._observers: List[Callable[[dict, dict, dict], None]] = list(packet_observers or [])

        # --- Detectors (ordered: cheapest / most likely to fire first) ---
        self._detectors: list = []
        self._init_detectors(config)

        # Hot-reload state
        self._rules_mtime: tuple = _mtimes(self._rule_paths)

        # Detector state pruning, driven by packet time (works for replay too)
        self._last_prune: float = 0.0

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

            # 1b. Enrichment — owning app, hostname, GeoIP
            context: Dict[str, Any] = {}
            if self._enricher is not None:
                try:
                    context = self._enricher.packet_context(meta, layer7)
                except Exception as exc:
                    logger.debug("Enrichment failed: %s", exc)

            if context:
                layer7["context"] = context  # lets detectors see the owning app

            # 2. Flow tracking
            flow = self._flow_tracker.update(meta)
            if flow is not None and (layer7 or context):
                _annotate_flow(flow, layer7, context)

            # 3. Threat intelligence checks
            try:
                alerts.extend(self._run_threat_intel(meta, layer7))
            except Exception as exc:
                logger.error("Threat-intel check raised: %s", exc)

            # 4. Run all detectors
            for detector in self._detectors:
                try:
                    for alert in detector.analyze(meta, layer7, flow):
                        alerts.append(alert)
                except Exception as exc:
                    logger.error("Detector %s raised: %s", detector.name, exc)

            self._maybe_prune(meta.get("timestamp") or time.time())

            if alerts:
                flow_info = _flow_context(flow) if flow is not None else None
                for alert in alerts:
                    if context:
                        alert.context = {**context, **alert.context}
                    # Flow facts travel with the alert: how much was exchanged,
                    # who opened the connection, how it ended.
                    if flow_info is not None and (alert.dst_ip or alert.flow_id):
                        if alert.flow_id is None:
                            alert.flow_id = flow.flow_id
                        if "flow" not in alert.context:
                            alert.context = {**alert.context, "flow": flow_info}

            for observer in self._observers:
                try:
                    observer(meta, layer7, context)
                except Exception as exc:
                    logger.debug("Packet observer failed: %s", exc)

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
        if not self._rule_paths:
            return False
        if not any(Path(p).exists() for p in self._rule_paths):
            logger.debug("Rules file not found: %s", ", ".join(self._rule_paths))
            return False
        mtimes = _mtimes(self._rule_paths)
        if mtimes == self._rules_mtime:
            return False

        new_rules = load_rule_files(self._rule_paths)
        with self._lock:
            for detector in self._detectors:
                if isinstance(detector, SignatureDetector):
                    detector.update_rules(new_rules)
                    self._rules_mtime = mtimes
                    logger.info(
                        "Hot-reloaded %d signature rules from %s",
                        len(new_rules),
                        ", ".join(self._rule_paths),
                    )
                    return True
        return False

    def rules(self) -> Dict[str, Any]:
        """The loaded signature rules with hit counts, plus every detector's name."""
        out: Dict[str, Any] = {"files": list(self._rule_paths), "rules": [], "problems": [],
                               "detectors": [d.name for d in self._detectors]}
        for detector in self._detectors:
            if isinstance(detector, SignatureDetector):
                out["rules"] = detector.rule_stats()
                out["problems"] = list(detector.problems)
                break
        return out

    def flows(self, limit: int = 200, sort: str = "recent") -> List[Dict[str, Any]]:
        """Snapshot of the connection table (most recent first by default)."""
        return self._flow_tracker.snapshot(limit=limit, sort=sort)

    def flow_counts(self) -> Dict[str, int]:
        return self._flow_tracker.counts()

    @property
    def stats(self) -> Dict[str, Any]:
        """Runtime statistics snapshot."""
        uptime = time.time() - self._start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "packets_processed": self._packets_processed,
            "packets_per_second": round(self._packets_processed / max(uptime, 1), 1),
            "active_flows": self._flow_tracker.active_count,
            "total_flows": self._flow_tracker.total_flows,
            "rules": sum(len(d._compiled) for d in self._detectors if isinstance(d, SignatureDetector)),
            "rule_problems": sum(len(d.problems) for d in self._detectors if isinstance(d, SignatureDetector)),
            "alert_stats": self._alert_manager.stats,
        }

    @property
    def alert_manager(self) -> AlertManager:
        return self._alert_manager

    def reload_intel(
        self,
        intel: Optional[ThreatIntel],
        tracker_domains: Optional[Dict[str, str]] = None,
        doh_hosts: Optional[set] = None,
        doh_ips: Optional[set] = None,
    ) -> None:
        """Swap in freshly downloaded threat-intel and privacy feeds."""
        with self._lock:
            self._intel = intel
            for detector in self._detectors:
                if isinstance(detector, TrackerDetector) and tracker_domains:
                    merged = dict(tracker_domains)
                    merged.update(detector.domains)
                    detector.domains = merged
                elif isinstance(detector, DohDetector):
                    detector.hosts |= set(doh_hosts or ())
                    detector.ips |= set(doh_ips or ())

    @property
    def enricher(self) -> Optional["Enricher"]:
        return self._enricher

    def add_detector(self, detector: BaseDetector) -> None:
        """Register an extra detector (the daemon's host-aware ones)."""
        with self._lock:
            self._detectors.append(detector)

    @property
    def intel(self) -> Optional[ThreatIntel]:
        return self._intel

    def add_packet_observer(self, observer: Callable[[dict, dict, dict], None]) -> None:
        self._observers.append(observer)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _maybe_prune(self, now: float) -> None:
        """Let every detector drop stale state about once a minute."""
        if self._last_prune == 0.0:
            self._last_prune = now
            return
        if now - self._last_prune < 60.0:
            return
        self._last_prune = now
        for detector in self._detectors:
            try:
                detector.prune(now)
            except Exception as exc:
                logger.error("Detector %s prune raised: %s", detector.name, exc)

    def _init_detectors(self, config: Dict[str, Any]) -> None:
        """Instantiate and register all configured detectors."""

        # Signature detector
        rules = load_rule_files(self._rule_paths) if self._rule_paths else []
        self._detectors.append(SignatureDetector(rules))
        if self._rule_paths:
            logger.info("Loaded %d signature rules from %s", len(rules), ", ".join(self._rule_paths))

        # Anomaly detectors
        anom_cfg = config.get("anomaly", {})
        self._detectors.append(
            AnomalyDetector(
                ewma_alpha=float(anom_cfg.get("ewma_alpha", 0.3)),
                sigma_threshold=float(anom_cfg.get("sigma_threshold", 4.0)),
                window_seconds=int(anom_cfg.get("window_seconds", 10)),
                min_rate_pps=float(anom_cfg.get("min_rate_pps", 100)),
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
        self._detectors.append(
            DgaDetector(
                nxdomain_threshold=int(beh_cfg.get("dga_nxdomain_threshold", 12)),
                window=float(beh_cfg.get("dga_window", 60)),
            )
        )
        self._detectors.append(HttpAttackDetector())
        self._detectors.append(
            DataExfiltrationDetector(
                threshold_bytes=int(beh_cfg.get("exfil_threshold_bytes", 100 * 1024 * 1024))
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
                    # The dashboard / menu bar app talking to our own API.
                    ignore_ports=[(config.get("daemon") or {}).get("api_port") or 0],
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
            # Cached live feeds (``pynids intel update``) extend the built-in
            # tracker and DoH lists when a feed directory is configured.
            feeds_dir = (config.get("intel") or {}).get("feeds_dir")
            tracker_extra: Dict[str, str] = {}
            doh_hosts: set = set()
            doh_ips: set = set()
            if feeds_dir:
                from .intel.feeds import load_doh, load_trackers
                tracker_extra = load_trackers(Path(feeds_dir))
                doh_hosts, doh_ips = load_doh(Path(feeds_dir))
            if stealth_cfg.get("trackers_enabled", True):
                self._detectors.append(TrackerDetector(extra_domains=tracker_extra))
            if stealth_cfg.get("doh_enabled", True):
                self._detectors.append(DohDetector(hosts=doh_hosts, ips=doh_ips))

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

        # Check TLS / QUIC server names — still visible when DNS is encrypted
        sni = (layer7.get("tls") or {}).get("sni") or (layer7.get("quic") or {}).get("sni")
        if sni and sni != dns_name:
            entry = self._intel.check_domain(sni)
            if entry:
                alerts.append(
                    Alert(
                        alert_type=AlertType.THREAT_INTEL,
                        severity=Severity(entry.severity),
                        message=(
                            f"Encrypted connection to known malicious host '{sni}' "
                            f"({entry.category}): {entry.description}"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=meta.get("dst_port"),
                        protocol=meta.get("protocol"),
                        mitre_technique="T1071.001",
                        tags=["threat_intel", "sni", entry.category],
                        confidence=1.0,
                        evidence={
                            "sni": sni,
                            "matched_indicator": entry.indicator,
                            "category": entry.category,
                        },
                    )
                )

        # Check plaintext HTTP Host headers — malware often skips DNS it controls
        http = layer7.get("http") or {}
        host = http.get("host") if http.get("direction") == "request" else None
        if host:
            host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            host = host.strip("[]").lower()
        if host and host not in (dns_name, sni):
            entry = self._intel.check_domain(host)
            if entry:
                alerts.append(
                    Alert(
                        alert_type=AlertType.THREAT_INTEL,
                        severity=Severity(entry.severity),
                        message=(
                            f"HTTP request to known malicious host '{host}' "
                            f"({entry.category}): {entry.description}"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=meta.get("dst_port"),
                        protocol=meta.get("protocol"),
                        mitre_technique="T1071.001",
                        tags=["threat_intel", "http", entry.category],
                        confidence=1.0,
                        evidence={
                            "host": host,
                            "uri": http.get("uri"),
                            "user_agent": http.get("user_agent"),
                            "matched_indicator": entry.indicator,
                            "category": entry.category,
                        },
                    )
                )

        return alerts


def _annotate_flow(flow: Any, layer7: Dict[str, Any], context: Dict[str, Any]) -> None:
    """Remember what the dissector and enricher learned about a flow."""
    proto = layer7.get("app_proto")
    if proto and flow.app_proto is None:
        flow.app_proto = proto
    if flow.server_name is None:
        name = ((layer7.get("tls") or {}).get("sni") or (layer7.get("quic") or {}).get("sni")
                or (layer7.get("http") or {}).get("host") or (layer7.get("dns") or {}).get("query_name")
                or context.get("remote_host"))
        if name:
            flow.server_name = str(name)[:253]
    if flow.app is None and context.get("app"):
        flow.app = context["app"]


def _flow_context(flow: Any) -> Dict[str, Any]:
    return {
        "initiator": flow.src_ip,
        "responder": f"{flow.dst_ip}:{flow.dst_port}",
        "state": flow.state.value,
        "outcome": flow.outcome,
        "history": flow.history,
        "packets": flow.packet_count,
        "bytes_out": flow.bytes_from_src,
        "bytes_in": flow.bytes_to_src,
        "duration": round(flow.duration, 2),
        "app_proto": flow.app_proto,
        "server_name": flow.server_name,
    }
