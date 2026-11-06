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
from ..alerts.allowlist import Allowlist
from ..detection.hostrisk import BaselineDetector, BaselineStore, C2Correlator, ProcessRiskDetector
from ..enrich import Enricher, GeoResolver, HostnameCache, ProcessResolver
from ..host.codesign import SignatureChecker
from ..host.dossier import IpLookup, LookupPrefetch
from ..host.inspector import HostInspector
from ..host.lan import LanInventory
from ..host.persistence import PersistenceIndex
from ..intel import feeds as feeds_mod
from ..intel.threat_intel import ThreatIntel
from ..paths import (
    DEFAULT_API_HOST, DEFAULT_API_PORT, anthropic_key_path, blocklist_path, console_owner_uid,
    daemon_config_path, data_dir, db_path, evidence_dir, geoip_dir, intel_dir, is_root,
    notifications_off_flag_path, paused_flag_path, soc_keys_path, token_path,
)
from ..sniffer import sniff_live
from .api import ServiceContext, make_server
from .live import LiveState
from .updater import Updater

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
        "retention_days": 30,   # delete stored alerts older than this (0 = keep forever)
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
    # Host-aware detection: code signatures, baseline, LAN inventory, C2 correlation.
    "host": {
        "signatures": True,
        "baseline": True,
        "baseline_learning_hours": 24,
        "lan_inventory": True,
        "lan_learning_hours": 1,
        "c2_correlation": True,
    },
    # External IP lookups (reverse DNS, RDAP, Shodan InternetDB).
    #   alerts — automatically, only for IPs in alerts at or above min_severity
    #   always — automatically for every alerting IP, any severity
    #   manual — only when you open an IP in the dashboard and ask
    "lookups": {
        "mode": "alerts",
        "min_severity": "MEDIUM",
    },
    # In-app updates: check GitHub for new commits; the dashboard / menu bar
    # app shows an Update button.  Nothing is installed without a click.
    "updates": {
        "check": True,
        "interval_hours": 6,
        "extras": "all",
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
    token = ""
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    if not token:
        token = secrets.token_urlsafe(32)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token + "\n")
    # Only the user this Mac's PyNIDS belongs to (and root) may read it: it
    # lets the menu bar app and CLI drive the API, which can block IPs.
    try:
        os.chmod(path, 0o600)
        uid = console_owner_uid() if is_root() else None
        if uid is not None:
            os.chown(path, uid, -1)
    except OSError as exc:
        logger.warning("Could not restrict %s: %s", path, exc)
    return token


def _chmod(path: Path, mode: int) -> None:
    try:
        if path.exists() and not path.is_symlink() and path.stat().st_uid == os.geteuid():
            os.chmod(path, mode)
    except OSError as exc:
        logger.debug("chmod %s failed: %s", path, exc)


def harden_permissions() -> None:
    """
    Tighten modes of data written by older versions (the daemon itself runs
    with umask 077).  The data directory stays traversable so the user's
    menu bar app can reach its token and the pause flag; alerts, captures,
    evidence and keys are root-only.  Threat-intel feeds are public data the
    user's CLI shows, so they stay readable.
    """
    root = data_dir()
    _chmod(root, 0o711)
    for name in ("events.db", "events.db-wal", "events.db-shm", "events.db-journal",
                 "allowlist.json", "last-update.json"):
        _chmod(root / name, 0o600 if name != "last-update.json" else 0o644)
    for path in (blocklist_path(), soc_keys_path(), anthropic_key_path()):
        _chmod(path, 0o600)
    for folder in (root / "captures", evidence_dir()):
        if folder.is_dir():
            _chmod(folder, 0o700)
            for dirpath, dirnames, filenames in os.walk(folder):
                for d in dirnames:
                    _chmod(Path(dirpath) / d, 0o700)
                for f in filenames:
                    _chmod(Path(dirpath) / f, 0o600)
    share_intel()


def share_intel() -> None:
    """Feeds and GeoIP databases are public data the user's CLI reads too."""
    folder = intel_dir()
    _chmod(folder, 0o755)
    for f in folder.glob("*"):
        if f.is_file():
            _chmod(f, 0o644)
    _chmod(geoip_dir(), 0o755)


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
    if options.api_port is not None:
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
        self._last_error_log: Dict[str, float] = {}
        # Set to end the current capture threads without stopping the daemon
        # (detection paused from the menu bar app or dashboard).
        self.capture_stop = threading.Event()
        self._capture_lock = threading.Lock()
        self._feeds_lock = threading.Lock()
        self._feeds_attempt = 0.0  # monotonic time of the last feed refresh attempt
        self.paused = paused_flag_path().exists()

        dcfg = self.cfg["daemon"]
        self.live = LiveState()

        # --- Enrichment ---
        hcfg = self.cfg["host"]
        self.processes = ProcessResolver() if dcfg.get("process_attribution", True) else None
        self.geo = GeoResolver() if dcfg.get("geoip", True) else None
        self.signatures = SignatureChecker() if hcfg.get("signatures", True) else None
        self.enricher = Enricher(processes=self.processes, geo=self.geo, hostnames=HostnameCache(),
                                 signatures=self.signatures)
        self.persistence = PersistenceIndex()
        lcfg = self.cfg["lookups"]
        self.lookups = IpLookup(db_path(), mode=str(lcfg.get("mode", "alerts")))

        # --- Alert pipeline ---
        am = self.cfg["alert_manager"]
        self.alerts = AlertManager(
            dedup_window=float(am.get("dedup_window", 60)),
            correlation_window=float(am.get("correlation_window", 120)),
            correlation_threshold=int(am.get("correlation_threshold", 3)),
            min_severity=Severity.LOW,
            suppression_rules=am.get("suppression", []),
        )
        self.allowlist = Allowlist(data_dir() / "allowlist.json")
        self.alerts.add_filter(self.allowlist)
        self.alerts.register_output(self.live)
        self.store = SQLiteOutput(path=str(db_path()), batch_size=100, flush_interval=2.0)
        self.alerts.register_output(self.store)
        self.alerts.register_output(LookupPrefetch(
            self.lookups, min_severity=Severity(str(lcfg.get("min_severity", "MEDIUM")).upper())))
        if hcfg.get("c2_correlation", True):
            self.alerts.register_output(C2Correlator(
                emit=self.alerts.add,
                infra_tags=lambda ip: ((self.lookups.cached(ip) or {}).get("internetdb") or {}).get("tags") or [],
            ))

        ncfg = self.cfg["notifications"]
        self.notifier = None
        if ncfg.get("enabled", True) and sys.platform == "darwin":
            from ..response.notify import NotificationOutput
            self.notifier = NotificationOutput(
                min_severity=Severity(str(ncfg.get("min_severity", "HIGH")).upper()),
                min_interval=float(ncfg.get("min_interval", 15)),
            )
            self.alerts.register_output(self.notifier)
            if notifications_off_flag_path().exists():
                self.notifier.enabled = False

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
        if self.signatures is not None:
            self.engine.add_detector(ProcessRiskDetector(self.signatures.lookup, self.persistence.for_program))
        self.baseline: Optional[BaselineDetector] = None
        if hcfg.get("baseline", True):
            self.baseline = BaselineDetector(
                BaselineStore(db_path()),
                learning_seconds=float(hcfg.get("baseline_learning_hours", 24)) * 3600,
            )
            self.engine.add_detector(self.baseline)
        self.lan = None
        if hcfg.get("lan_inventory", True):
            self.lan = LanInventory(
                db_path(), emit=self.alerts.add, hostname=self.enricher.hostnames.lookup,
                learning_seconds=float(hcfg.get("lan_learning_hours", 1)) * 3600,
                own_ips=lambda: self.enricher.local_ips,
            )
        self.inspector = HostInspector(
            live=self.live, signatures=self.signatures or SignatureChecker(),
            persistence=self.persistence, lookups=self.lookups, lan=self.lan,
            hostnames=self.enricher.hostnames, geo=self.enricher.geo,
            intel=lambda: self.engine.intel, baseline=self.baseline, db_path=db_path(),
        )

        # --- API ---
        explain = investigate = None
        from ..ai import explain as ai_explain
        if ai_explain.is_available():
            from ..ai.investigate import Toolbox, investigate as ai_investigate
            explain = lambda alert: ai_explain.explain_alert(alert, extra=self.explain_context(alert))  # noqa: E731
            investigate = lambda q: ai_investigate(q, Toolbox(self.inspector, self.live))  # noqa: E731
        ucfg = self.cfg["updates"]
        self.updater = Updater(
            state_file=data_dir() / "last-update.json",
            # The process re-executes itself into the new code (see reexec).
            on_restart=self.restart_for_update,
            broadcast=self.live.broadcast,
            interval_hours=float(ucfg.get("interval_hours", 6)) if ucfg.get("check", True) else 0,
            extras=str(ucfg.get("extras", "all")),
        )
        from ..soc.keys import KeyStore
        from ..soc.workbench import LocalSource, Workbench
        self.workbench = Workbench(
            db_path(), keys=KeyStore(soc_keys_path()),
            local=LocalSource(intel=lambda: self.engine.intel, inspector=self.inspector,
                              live=self.live, db_path=db_path()),
        )
        from ..soc.mail.store import EmailStore
        self.emails = EmailStore(evidence_dir() / "email", db_path())
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
            set_detection=self.set_detection,
            inspector=self.inspector,
            allowlist=self.allowlist,
            investigate=investigate,
            baseline=self.baseline,
            updater=self.updater,
            workbench=self.workbench,
            emails=self.emails,
            set_notifications=self.set_notifications,
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
            "paused": self.paused,
            "notifications": bool(self.notifier and self.notifier.enabled),
            "auto_block": bool(self.cfg["response"].get("auto_block")),
            "blocking_available": self.blocker is not None,
            "ai": ai_explain.is_available() and bool(ai_explain.load_api_key()),
            "feeds_age_hours": _hours(feeds_mod.oldest_fetch_age(intel_dir())),
            "recording": str(self.recorder.current) if self.recorder else None,
            "data_dir": str(data_dir()),
            "signatures": bool(self.signatures and self.signatures.available),
            "lookup_mode": self.lookups.mode,
            "baseline_learning": bool(self.baseline and self.baseline.learning),
            "lan_inventory": self.lan is not None,
            "local_ips": sorted(ip for ip in self.enricher.local_ips
                                if ":" not in ip and not ip.startswith("127.")),
            "allowlisted": self.allowlist.hits,
            "update": self.updater.brief(),
        }

    def explain_context(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Host facts sent to Claude with an alert (program signature, IP dossier)."""
        ctx = alert.get("context") or {}
        extra: Dict[str, Any] = {}
        exe = ctx.get("exe") or (alert.get("evidence") or {}).get("exe")
        try:
            if exe:
                prog = self.inspector.program(exe, with_hash=False)
                extra["program"] = {k: prog.get(k) for k in ("exe", "signature", "assessment", "launchd",
                                                             "usual_countries", "first_network_use")}
            ip = ctx.get("remote_ip") or alert.get("dst_ip")
            if ip:
                # Asking Claude is a deliberate user action, so a fresh lookup is fine.
                d = self.inspector.dossier(ip, external=self.lookups.mode != "manual")
                local = d["local"]
                extra["remote"] = {
                    "ip": ip, "hostname_seen": local.get("remote_host"), "apps": local.get("apps"),
                    "intel": local.get("intel"), "bytes": local.get("bytes"),
                    "lookup": {k: (d.get("external") or {}).get(k) for k in ("ptr", "rdap", "internetdb")},
                }
        except Exception as exc:  # noqa: BLE001 — context is best-effort
            logger.debug("explain context failed: %s", exc)
        return extra

    def refresh_feeds(self) -> List[Dict[str, Any]]:
        # One refresh at a time: the API button, the startup fetch, and the
        # periodic refresh would otherwise download and rebuild in parallel.
        with self._feeds_lock:
            self._feeds_attempt = time.monotonic()
            results = feeds_mod.update_feeds(intel_dir())
            share_intel()
            intel = _build_intel(self.cfg)
            doh_hosts, doh_ips = feeds_mod.load_doh(intel_dir())
            self.engine.reload_intel(intel, feeds_mod.load_trackers(intel_dir()), doh_hosts, doh_ips)
        self.live.broadcast("intel", {"updated": time.time()})
        return [r.__dict__ for r in results]

    def set_notifications(self, enabled: bool) -> bool:
        """Switch macOS notifications on or off.  The choice survives restarts."""
        if self.notifier is None:
            return False
        self.notifier.enabled = bool(enabled)
        flag = notifications_off_flag_path()
        try:
            if enabled:
                flag.unlink(missing_ok=True)
            else:
                flag.write_text(f"{time.time()}\n", encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not save the notification setting: %s", exc)
        return self.notifier.enabled

    def restart_for_update(self) -> None:
        """Shut down and re-execute (exit code 75 → :func:`reexec`) into the updated code."""
        self._restart_requested = True
        self.capture_stop.set()
        self.stop_event.set()

    # ------------------------------------------------------------------

    def _capture(self, iface: str, record: bool, stop: threading.Event) -> None:
        raw_cb = self.recorder.write if (record and self.recorder) else None
        while not stop.is_set():
            try:
                sniff_live(
                    iface=iface,
                    engine_callback=self.engine.process_packet,
                    bpf_filter=self.cfg["daemon"].get("bpf") or None,
                    raw_callback=raw_cb,
                    stop_event=stop,
                )
            except Exception as exc:  # noqa: BLE001
                msg = f"{time.strftime('%H:%M:%S')} capture on {iface} failed: {exc}"
                logger.error(msg)
                self.capture_errors.append(msg)
                if "Permission" in str(exc) or "permission" in str(exc):
                    self.state = "needs-root"
                    return
                stop.wait(5)

    _TICK = 2.0  # seconds between _periodic iterations

    def _step(self, name: str, fn: Any) -> None:
        """Run one periodic task; a failure is logged (at most every 5 min) and skipped."""
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — never let one task end the loop
            now = time.monotonic()
            if now - self._last_error_log.get(name, -1e9) >= 300:
                self._last_error_log[name] = now
                logger.error("Periodic task %s failed: %s", name, exc)
            else:
                logger.debug("Periodic task %s failed: %s", name, exc)

    def _expire_blocks(self) -> None:
        for ip in self.blocker.expire():
            self.live.broadcast("unblock", {"ip": ip, "expired": True})

    def _follow_default_route(self) -> None:
        current = default_interface()
        if current and self.interfaces and current != self.interfaces[0]:
            logger.warning("Default interface changed %s → %s; restarting capture",
                           self.interfaces[0], current)
            if _under_launchd():
                # Start over in a fresh process (exit 75 → reexec).
                self._restart_requested = True
                self.capture_stop.set()
                self.stop_event.set()
            else:
                # Started by hand: move the capture over in place.
                self._restart_capture()

    def _maybe_refresh_feeds(self, refresh_s: float) -> None:
        # A feed that keeps failing leaves the cache "stale" forever;
        # don't re-download every feed every 10 minutes because of it.
        retry_s = min(refresh_s, 3600.0)
        if (feeds_mod.oldest_fetch_age(intel_dir()) > refresh_s
                and time.monotonic() - self._feeds_attempt > retry_s
                and not self._feeds_lock.locked()):
            threading.Thread(target=self.refresh_feeds, daemon=True).start()

    def _periodic(self) -> None:
        refresh_s = float(self.cfg["daemon"].get("feed_refresh_hours", 6)) * 3600
        tick = 0
        while not self.stop_event.wait(self._TICK):
            tick += 1
            self._step("alert flush", self.store.flush)
            if tick % 15 == 0 and self.baseline is not None:
                self._step("baseline flush", self.baseline.store.flush)
            if tick % 30 == 0 and self.lan is not None and not self.paused:
                self._step("LAN refresh", self.lan.refresh)
            if self.blocker and tick % 15 == 0:
                self._step("block expiry", self._expire_blocks)
            if tick % 10 == 0 and self.interfaces and self.cfg["daemon"]["interface"] == "auto":
                self._step("interface check", self._follow_default_route)
            if refresh_s > 0 and tick % 300 == 0 and not self.paused:
                self._step("feed refresh", lambda: self._maybe_refresh_feeds(refresh_s))
            if tick % 1800 == 0:  # hourly
                self._step("retention", lambda: self.store.prune(
                    float(self.cfg["daemon"].get("retention_days") or 0)))

    def _start_capture(self) -> None:
        dcfg = self.cfg["daemon"]
        iface = dcfg["interface"]
        if iface == "auto":
            iface = default_interface() or "en0"
        self.capture_stop = threading.Event()
        stop = self.capture_stop
        self.interfaces = [iface]
        threading.Thread(target=self._capture, args=(iface, True, stop),
                         name=f"capture-{iface}", daemon=True).start()
        lo = dcfg.get("loopback_interface", "lo0")
        if dcfg.get("loopback", True) and lo != iface:
            self.interfaces.append(lo)
            threading.Thread(target=self._capture, args=(lo, False, stop),
                             name=f"capture-{lo}", daemon=True).start()
        self.state = "running"

    def _restart_capture(self) -> None:
        """Stop the capture threads and start them on the current default interface."""
        with self._capture_lock:
            if self.paused or self.state != "running":
                return
            self.capture_stop.set()
            self._start_capture()

    def set_detection(self, enabled: bool) -> Dict[str, Any]:
        """Pause or resume capture + detection.  The choice survives restarts."""
        with self._capture_lock:
            flag = paused_flag_path()
            if not enabled and not self.paused:
                self.paused = True
                flag.parent.mkdir(parents=True, exist_ok=True)
                flag.write_text(f"{time.time()}\n", encoding="utf-8")
                self.capture_stop.set()
                self.interfaces = []
                # Idle everything that only exists to feed detection.
                if self.processes:
                    self.processes.pause()
                if self.notifier:
                    self.notifier.discard_pending()
                if self.state == "running":
                    self.state = "paused"
                logger.warning("Detection paused")
                self.live.broadcast("detection", {"enabled": False})
            elif enabled and self.paused:
                self.paused = False
                flag.unlink(missing_ok=True)
                if self.processes:
                    self.processes.resume()
                if self.state == "paused":
                    self._start_capture()
                logger.warning("Detection resumed")
                self.live.broadcast("detection", {"enabled": True})
        return {"enabled": not self.paused, "state": self.state}

    def run(self) -> int:
        dcfg = self.cfg["daemon"]
        threading.Thread(target=self.server.serve_forever, name="api", daemon=True).start()
        logger.info("API + dashboard on http://%s:%s", dcfg["api_host"], dcfg["api_port"])

        if self.processes:
            self.processes.start()
            if self.paused:
                self.processes.pause()
        if self.signatures:
            self.signatures.start()
        self.lookups.start()
        if self.lan is not None and not self.paused:
            threading.Thread(target=self.lan.refresh, name="lan", daemon=True).start()
        if self.blocker:
            try:
                self.blocker.sync()
            except Exception as exc:  # noqa: BLE001
                logger.error("Could not re-apply blocklist: %s", exc)

        if feeds_mod.oldest_fetch_age(intel_dir()) == float("inf"):
            threading.Thread(target=self.refresh_feeds, name="feeds", daemon=True).start()

        threading.Thread(target=self._periodic, name="periodic", daemon=True).start()
        self.updater.start()

        if not self.options.no_capture and not self.root and not os.access("/dev/bpf0", os.R_OK):
            # Packet capture needs root (or ChmodBPF); keep the API up so the
            # dashboard can say so instead of silently showing nothing.
            self.state = "needs-root"
            logger.error("Packet capture needs root — run with sudo or install the daemon")
        elif not self.options.no_capture:
            if dcfg.get("record_pcap"):
                from .recorder import PcapRing
                self.recorder = PcapRing(
                    data_dir() / "captures",
                    max_mb=int(dcfg.get("record_max_mb", 50)),
                    max_files=int(dcfg.get("record_files", 10)),
                )
            if self.paused:
                self.state = "paused"
                logger.info("Detection is paused — not capturing until resumed")
            else:
                self._start_capture()
        else:
            self.state = "idle"

        def _terminate(signum, frame):  # noqa: ARG001
            self.capture_stop.set()
            self.stop_event.set()

        signal.signal(signal.SIGTERM, _terminate)
        signal.signal(signal.SIGINT, _terminate)
        signal.signal(signal.SIGHUP, _terminate)

        while not self.stop_event.wait(1.0):
            pass
        self.shutdown()
        # Exit code 75 (EX_TEMPFAIL): start over in a fresh process (network
        # change, update); a clean stop exits 0.
        return 75 if self._restart_requested else 0

    def shutdown(self) -> None:
        self.state = "stopping"
        logger.info("Shutting down")
        self.live.close_streams()
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:  # noqa: BLE001
            pass
        self.capture_stop.set()
        self.updater.stop()
        if self.processes:
            self.processes.stop()
        if self.signatures:
            self.signatures.stop()
        stop_lookups = getattr(self.lookups, "stop", None)
        if callable(stop_lookups):
            try:
                stop_lookups()
            except Exception as exc:  # noqa: BLE001
                logger.debug("lookup shutdown failed: %s", exc)
        from ..host.lan import kill_scans
        kill_scans()
        if self.baseline is not None:
            self.baseline.store.flush()
        if self.recorder:
            self.recorder.close()
        # A network change (exit 75) restarts us within seconds: keep the
        # blocks.  A real stop leaves nothing behind in the firewall; the
        # ledger re-applies unexpired blocks on the next start.
        if self.blocker and not self._restart_requested:
            try:
                self.blocker.unload()
            except Exception as exc:  # noqa: BLE001
                logger.error("Could not unload pf rules: %s", exc)
        self.alerts.close()
        logger.info("Stopped cleanly")


def _under_launchd() -> bool:
    from .launchd import LABEL
    return os.environ.get("XPC_SERVICE_NAME") == LABEL or os.getppid() == 1


def _hours(seconds: float) -> Optional[float]:
    return None if seconds == float("inf") else round(seconds / 3600, 1)


def run_daemon(options: DaemonOptions) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Alerts, captures, evidence and keys must not be readable by other accounts.
    os.umask(0o077)
    harden_permissions()
    daemon = Daemon(options)
    return daemon.run()


def reexec() -> None:
    """
    Replace this process with a fresh interpreter running the same command,
    so updated code is actually loaded (an in-process restart would keep the
    old modules, and stray threads still holding the old state).
    """
    argv = [sys.executable, "-m", "pynids", *sys.argv[1:]]
    logger.warning("Restarting: %s", " ".join(argv))
    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:  # noqa: BLE001
            pass
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execv(sys.executable, argv)
    except OSError as exc:
        # launchd's KeepAlive brings us back after an exit; by hand, say so.
        logger.error("Could not restart (%s); exiting with 75", exc)
        sys.exit(75)
