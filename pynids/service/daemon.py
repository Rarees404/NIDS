"""
The PyNIDS background daemon.

One long-running process that does everything:

* captures the active network interface **and** loopback (for localhost
  probes), feeding the full detection engine (signatures, anomalies,
  behavioural, X-Ray stealth detectors, threat intel)
* enriches every packet with the owning app, the hostname, and GeoIP
* persists alerts to SQLite, keeps live stats in memory, and serves the
  local API + web dashboard
* posts macOS notifications for important alerts
* optionally auto-blocks confirmed-malicious IPs with pf
* refreshes threat-intel feeds every few hours
* restarts capture when you switch networks (Wi-Fi → Ethernet, VPN)

Under launchd (``pynids daemon install``) it runs as root at boot.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import __version__
from ..alerts.manager import AlertManager
from ..alerts.model import Severity
from ..alerts.outputs.sqlite_out import SQLiteOutput
from ..config import DEFAULT_CONFIG, _deep_merge, load_config
from ..engine import DetectionEngine
from ..enrich import Enricher, GeoResolver, HostnameCache, ProcessResolver
from ..intel import feeds as feeds_mod
from ..intel.threat_intel import ThreatIntel
from ..paths import (
    DEFAULT_API_HOST, DEFAULT_API_PORT, daemon_config_path, data_dir, db_path,
    intel_dir, is_root, token_path,
)
from ..sniffer import sniff_live
from .api import ServiceContext, make_server
from .live import LiveState

logger = logging.getLogger("pynids.daemon")

# Settings specific to the daemon, merged under the ``daemon:`` key.
DAEMON_DEFAULTS: Dict[str, Any] = {
    "daemon": {
        "interface": "auto",
        "loopback": True,
        "loopback_interface": "lo0",
        "bpf": "",
        "api_host": DEFAULT_API_HOST,
        "api_port": DEFAULT_API_PORT,
        "feed_refresh_hours": 6,
        "process_attribution": True,
        "geoip": True,
        "record_pcap": False,
        "record_max_mb": 50,
        "record_files": 10,
    },
    "notifications": {
        "enabled": True,
        "min_severity": "HIGH",
        "min_interval": 15,
    },
    "response": {
        "auto_block": False,
        "dry_run": False,
        "min_severity": "CRITICAL",
        "alert_types": ["threat_intel", "correlation"],
        "ttl": 3600,
        "never_block": [],
    },
    "alert_manager": {
        "dedup_window": 60,
        "correlation_window": 120,
        "correlation_threshold": 3,
    },
}


@dataclass
class DaemonOptions:
    config: Optional[str] = None
    rules: Optional[str] = None
    interface: Optional[str] = None
    api_port: Optional[int] = None
    no_capture: bool = False
    auto_block: Optional[bool] = None
    record: Optional[bool] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def default_interface() -> Optional[str]:
    """Interface carrying the default route (en0 on most Macs)."""
    for family in ("-inet", "-inet6"):
        try:
            out = subprocess.run(
                ["/sbin/route", "-n", "get", family, "default"],
                capture_output=True, text=True, timeout=5, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.search(r"interface:\s*(\S+)", out)
        if m:
            return m.group(1)
    return None


def ensure_token() -> str:
    path = token_path()
    try:
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n", encoding="utf-8")
    # Readable by local users so the menu bar app / CLI can use the API.
    os.chmod(path, 0o644)
    return token


def build_config(options: DaemonOptions) -> Dict[str, Any]:
    cfg = _deep_merge(DEFAULT_CONFIG, DAEMON_DEFAULTS)
    for candidate in (options.config, str(daemon_config_path())):
        if candidate and Path(candidate).exists():
            cfg = _deep_merge(cfg, load_config(candidate))
            break
    cfg = _deep_merge(cfg, options.extra)
    cfg.setdefault("stealth", {})["enabled"] = True
    cfg.setdefault("intel", {})["feeds_dir"] = str(intel_dir())
    if options.interface:
        cfg["daemon"]["interface"] = options.interface
    if options.api_port:
        cfg["daemon"]["api_port"] = options.api_port
    if options.auto_block is not None:
        cfg["response"]["auto_block"] = options.auto_block
    if options.record is not None:
        cfg["daemon"]["record_pcap"] = options.record
    return cfg


def _build_intel(cfg: Dict[str, Any]) -> ThreatIntel:
    intel_cfg = cfg.get("intel", {})
    intel = ThreatIntel(
        bad_ips_path=intel_cfg.get("bad_ips_file"),
        malicious_domains_path=intel_cfg.get("malicious_domains_file"),
    )
    added = feeds_mod.load_into(intel, intel_dir())
    logger.info("Threat intel: %d cached feed indicators loaded", added)
    return intel


class Daemon:
    def __init__(self, options: DaemonOptions) -> None:
        self.options = options
        self.cfg = build_config(options)
        self.stop_event = threading.Event()
        self.started = time.time()
        self.root = is_root()
        self.state = "starting"
        self.capture_errors: List[str] = []
        self.interfaces: List[str] = []
        self.recorder: Any = None
        self._restart_requested = False

        dcfg = self.cfg["daemon"]
        self.live = LiveState()

        # --- Enrichment ---
        self.processes = ProcessResolver() if dcfg.get("process_attribution", True) else None
        self.geo = GeoResolver() if dcfg.get("geoip", True) else None
        self.enricher = Enricher(processes=self.processes, geo=self.geo, hostnames=HostnameCache())

        # --- Alert pipeline ---
        am = self.cfg["alert_manager"]
        self.alerts = AlertManager(
            dedup_window=float(am.get("dedup_window", 60)),
            correlation_window=float(am.get("correlation_window", 120)),
            correlation_threshold=int(am.get("correlation_threshold", 3)),
            min_severity=Severity.LOW,
            suppression_rules=am.get("suppression", []),
        )
        self.alerts.register_output(self.live)
        self.store = SQLiteOutput(path=str(db_path()), batch_size=100, flush_interval=2.0)
        self.alerts.register_output(self.store)

        ncfg = self.cfg["notifications"]
        self.notifier = None
        if ncfg.get("enabled", True) and sys.platform == "darwin":
            from ..response.notify import NotificationOutput
            self.notifier = NotificationOutput(
                min_severity=Severity(str(ncfg.get("min_severity", "HIGH")).upper()),
                min_interval=float(ncfg.get("min_interval", 15)),
            )
            self.alerts.register_output(self.notifier)

        rcfg = self.cfg["response"]
        self.blocker = None
        if sys.platform == "darwin" and (self.root or rcfg.get("dry_run")):
            from ..response.pf import AutoBlockPolicy, PfBlocker
            self.blocker = PfBlocker(
                never_block=rcfg.get("never_block", []), dry_run=bool(rcfg.get("dry_run")),
            )
            if rcfg.get("auto_block"):
                self.alerts.register_output(AutoBlockPolicy(
                    self.blocker,
                    min_severity=Severity(str(rcfg.get("min_severity", "CRITICAL")).upper()),
                    alert_types=rcfg.get("alert_types", ["threat_intel", "correlation"]),
                    ttl=float(rcfg.get("ttl", 3600)),
                    on_block=lambda entry, alert: self.live.broadcast("block", entry.__dict__),
                ))

        # --- Engine ---
        self.engine = DetectionEngine(
            config=self.cfg,
            rules_path=options.rules,
            intel=_build_intel(self.cfg),
            alert_manager=self.alerts,
            enricher=self.enricher,
            packet_observers=[self.live.observe_packet],
        )

        # --- API ---
        explain = None
        from ..ai import explain as ai_explain
        if ai_explain.is_available():
            explain = ai_explain.explain_alert
        self.token = ensure_token()
        self.api_ctx = ServiceContext(
            live=self.live,
            token=self.token,
            db_path=db_path(),
            status=self.status,
            blocker=self.blocker,
            notifier=self.notifier,
            explain=explain,
            update_feeds=self.refresh_feeds,
            feed_status=lambda: feeds_mod.feed_status(intel_dir()),
        )
        self.server = make_server(self.api_ctx, dcfg["api_host"], int(dcfg["api_port"]))

    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        stats = self.engine.stats
        from ..ai import explain as ai_explain
        return {
            "state": self.state,
            "version": __version__,
            "root": self.root,
            "interfaces": self.interfaces,
            "capture_errors": self.capture_errors[-5:],
            "uptime": round(time.time() - self.started),
            "packets": stats["packets_processed"],
            "active_flows": stats["active_flows"],
            "process_attribution": bool(self.processes and self.processes.available),
            "attributed_sockets": self.processes.size if self.processes else 0,
            "geoip": bool(self.geo and self.geo.available),
            "hostnames_learned": len(self.enricher.hostnames),
            "notifications": bool(self.notifier and self.notifier.enabled),
            "auto_block": bool(self.cfg["response"].get("auto_block")),
            "blocking_available": self.blocker is not None,
            "ai": ai_explain.is_available() and bool(ai_explain.load_api_key()),
            "feeds_age_hours": _hours(feeds_mod.oldest_fetch_age(intel_dir())),
            "recording": str(self.recorder.current) if self.recorder else None,
            "data_dir": str(data_dir()),
        }

    def refresh_feeds(self) -> List[Dict[str, Any]]:
        results = feeds_mod.update_feeds(intel_dir())
        intel = _build_intel(self.cfg)
        doh_hosts, doh_ips = feeds_mod.load_doh(intel_dir())
        self.engine.reload_intel(intel, feeds_mod.load_trackers(intel_dir()), doh_hosts, doh_ips)
        self.live.broadcast("intel", {"updated": time.time()})
        return [r.__dict__ for r in results]

    # ------------------------------------------------------------------

    def _capture(self, iface: str, record: bool) -> None:
        raw_cb = self.recorder.write if (record and self.recorder) else None
        while not self.stop_event.is_set():
            try:
                sniff_live(
                    iface=iface,
                    engine_callback=self.engine.process_packet,
                    bpf_filter=self.cfg["daemon"].get("bpf") or None,
                    raw_callback=raw_cb,
                    stop_event=self.stop_event,
                )
            except Exception as exc:  # noqa: BLE001
                msg = f"{time.strftime('%H:%M:%S')} capture on {iface} failed: {exc}"
                logger.error(msg)
                self.capture_errors.append(msg)
                if "Permission" in str(exc) or "permission" in str(exc):
                    self.state = "needs-root"
                    return
                self.stop_event.wait(5)

    def _periodic(self) -> None:
        refresh_s = float(self.cfg["daemon"].get("feed_refresh_hours", 6)) * 3600
        tick = 0
        while not self.stop_event.wait(2.0):
            tick += 1
            self.store.flush()
            if self.blocker and tick % 15 == 0:
                for ip in self.blocker.expire():
                    self.live.broadcast("unblock", {"ip": ip, "expired": True})
            if tick % 10 == 0 and self.interfaces and self.cfg["daemon"]["interface"] == "auto":
                current = default_interface()
                if current and current != self.interfaces[0]:
                    logger.warning("Default interface changed %s → %s; restarting capture",
                                   self.interfaces[0], current)
                    self._restart_requested = True
                    self.stop_event.set()
            if refresh_s > 0 and tick % 300 == 0:
                if feeds_mod.oldest_fetch_age(intel_dir()) > refresh_s:
                    threading.Thread(target=self.refresh_feeds, daemon=True).start()

    def run(self) -> int:
        dcfg = self.cfg["daemon"]
        threading.Thread(target=self.server.serve_forever, name="api", daemon=True).start()
        logger.info("API + dashboard on http://%s:%s", dcfg["api_host"], dcfg["api_port"])

        if self.processes:
            self.processes.start()
        if self.blocker:
            try:
                self.blocker.sync()
            except Exception as exc:  # noqa: BLE001
                logger.error("Could not re-apply blocklist: %s", exc)

        if feeds_mod.oldest_fetch_age(intel_dir()) == float("inf"):
            threading.Thread(target=self.refresh_feeds, name="feeds", daemon=True).start()

        threading.Thread(target=self._periodic, name="periodic", daemon=True).start()

        if not self.options.no_capture and not self.root and not os.access("/dev/bpf0", os.R_OK):
            # Packet capture needs root (or ChmodBPF); keep the API up so the
            # dashboard can say so instead of silently showing nothing.
            self.state = "needs-root"
            logger.error("Packet capture needs root — run with sudo or install the daemon")
        elif not self.options.no_capture:
            iface = dcfg["interface"]
            if iface == "auto":
                iface = default_interface() or "en0"
            self.interfaces = [iface]
            if dcfg.get("record_pcap"):
                from .recorder import PcapRing
                self.recorder = PcapRing(
                    data_dir() / "captures",
                    max_mb=int(dcfg.get("record_max_mb", 50)),
                    max_files=int(dcfg.get("record_files", 10)),
                )
            threading.Thread(target=self._capture, args=(iface, True),
                             name=f"capture-{iface}", daemon=True).start()
            lo = dcfg.get("loopback_interface", "lo0")
            if dcfg.get("loopback", True) and lo != iface:
                self.interfaces.append(lo)
                threading.Thread(target=self._capture, args=(lo, False),
                                 name=f"capture-{lo}", daemon=True).start()
            self.state = "running"
        else:
            self.state = "idle"

        def _terminate(signum, frame):  # noqa: ARG001
            self.stop_event.set()

        signal.signal(signal.SIGTERM, _terminate)
        signal.signal(signal.SIGINT, _terminate)
        signal.signal(signal.SIGHUP, _terminate)

        while not self.stop_event.wait(1.0):
            pass
        self.shutdown()
        # Exit code 75 (EX_TEMPFAIL) tells launchd to restart us promptly
        # on a network change; a clean stop exits 0.
        return 75 if self._restart_requested else 0

    def shutdown(self) -> None:
        self.state = "stopping"
        logger.info("Shutting down")
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:  # noqa: BLE001
            pass
        if self.processes:
            self.processes.stop()
        if self.recorder:
            self.recorder.close()
        self.alerts.close()


def _hours(seconds: float) -> Optional[float]:
    return None if seconds == float("inf") else round(seconds / 3600, 1)


def run_daemon(options: DaemonOptions) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    daemon = Daemon(options)
    return daemon.run()
