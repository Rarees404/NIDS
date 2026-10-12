"""
Host-aware detectors: they judge the *program* behind the traffic, not
just the packets.

* :class:`ProcessRiskDetector` — an unsigned, ad-hoc-signed, or tampered
  binary, or one running from a place malware hides (``/tmp``, hidden
  folders, ``/Users/Shared`` …), is talking to the internet.
* :class:`BaselineDetector` — learns what is normal for this Mac, then
  flags change: a program that never used the network before, or an app
  suddenly talking to a country it never contacted.
* :class:`C2Correlator` — an alert output that joins independent signals
  (beaconing, blocklist hits, an untrusted binary, a brand-new program,
  infrastructure tagged as C2) for the same program and server into one
  CRITICAL "likely command-and-control" alert.  One signal alone is often
  noise; two or more different ones together rarely are.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow
from ..host import codesign
from ..protocols.stealth import classify_ip
from .base import BaseDetector

logger = logging.getLogger(__name__)

# Browsers talk to every country on Earth; per-country baselines would be noise.
BROWSERS = frozenset({
    "Safari / WebKit", "Safari", "Google Chrome", "Google Chrome Canary", "Firefox",
    "Firefox Nightly", "Arc", "Brave Browser", "Microsoft Edge", "Opera", "Vivaldi",
    "Chromium", "Orion", "Zen", "Zen Browser", "DuckDuckGo", "Tor Browser", "Dia",
})


def _outbound_public(meta: dict, context: dict) -> bool:
    return context.get("direction") == "outbound" and classify_ip(meta.get("dst_ip")) == "public"


# ---------------------------------------------------------------------------
# Untrusted binaries on the network
# ---------------------------------------------------------------------------

class ProcessRiskDetector(BaseDetector):
    """
    Alert once per executable when an untrusted program reaches the internet.

    Args:
        signatures: ``exe -> Signature | None`` (non-blocking lookup).
        persistence: optional ``exe -> [launchd jobs]`` for the evidence.
    """

    def __init__(
        self,
        signatures: Callable[[str], Optional[Dict[str, Any]]],
        persistence: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
    ) -> None:
        self._signatures = signatures
        self._persistence = persistence
        self._done: Set[str] = set()

    @property
    def name(self) -> str:
        return "process_risk"

    def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
        context = layer7.get("context") or {}
        exe = context.get("exe")
        if not exe or exe in self._done or context.get("system_process"):
            return
        if not _outbound_public(meta, context):
            return
        sig = self._signatures(exe)
        if sig is None:  # not checked yet — the next packet will see it
            return
        self._done.add(exe)
        verdict = codesign.assess(exe, sig)
        if verdict["risk"] == 0:
            return
        severity = {1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH}[verdict["risk"]]
        app = context.get("app") or exe.rsplit("/", 1)[-1]
        jobs = []
        if self._persistence:
            try:
                jobs = self._persistence(exe)
            except Exception:  # noqa: BLE001
                jobs = []
        reasons = " and ".join(verdict["reasons"]) or "it is not signed by a known developer"
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=severity,
            message=f"Untrusted program on the network: {app} ({reasons})",
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            rule_id="HOST-PROCESS-RISK",
            mitre_technique="T1036" if "odd_path" in verdict["flags"] else "T1553",
            tags=["host_risk", "untrusted_binary", *verdict["flags"]],
            confidence={1: 0.4, 2: 0.65, 3: 0.85}[verdict["risk"]],
            evidence={
                "exe": exe,
                "signature": sig.get("status"),
                "signature_label": sig.get("label") or codesign.LABELS.get(sig.get("status")),
                "authority": sig.get("authority"),
                "team_id": sig.get("team_id"),
                "flags": verdict["flags"],
                "reasons": verdict["reasons"],
                "launchd_jobs": [{"label": j["label"], "plist": j["plist"]} for j in jobs[:5]],
                "pid": context.get("pid"),
            },
        )


# ---------------------------------------------------------------------------
# Baseline: new programs and new countries
# ---------------------------------------------------------------------------

class BaselineStore:
    """``(subject, kind, value)`` facts with first-seen times, kept in SQLite."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else None
        self._facts: Dict[Tuple[str, str, str], float] = {}
        self._dirty: Dict[Tuple[str, str, str], float] = {}
        self._lock = threading.Lock()
        self.created = time.time()
        self._load()

    def _connect(self) -> Optional[sqlite3.Connection]:
        if not self.db_path:
            return None
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.execute("CREATE TABLE IF NOT EXISTS baseline (subject TEXT, kind TEXT, value TEXT,"
                         " first_seen REAL, PRIMARY KEY (subject, kind, value))")
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            return conn
        except sqlite3.Error as exc:
            logger.debug("baseline db unavailable: %s", exc)
            return None

    def _load(self) -> None:
        conn = self._connect()
        if conn is None:
            return
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'baseline_created'").fetchone()
            if row:
                self.created = float(row[0])
            else:
                conn.execute("INSERT INTO meta VALUES ('baseline_created', ?)", (str(self.created),))
                conn.commit()
            for subject, kind, value, first in conn.execute("SELECT * FROM baseline"):
                self._facts[(subject, kind, value)] = first
        finally:
            conn.close()

    def first_seen(self, subject: str, kind: str, value: str = "") -> Optional[float]:
        return self._facts.get((subject, kind, value))

    def add(self, subject: str, kind: str, value: str = "", ts: Optional[float] = None) -> bool:
        """Record a fact; True if it is new."""
        key = (subject, kind, value)
        if key in self._facts:
            return False
        with self._lock:
            ts = ts or time.time()
            self._facts[key] = ts
            self._dirty[key] = ts
        return True

    def flush(self) -> None:
        with self._lock:
            dirty, self._dirty = self._dirty, {}
        if not dirty:
            return
        conn = self._connect()
        if conn is None:
            return
        try:
            conn.executemany("INSERT OR IGNORE INTO baseline VALUES (?, ?, ?, ?)",
                             [(*k, v) for k, v in dirty.items()])
            conn.commit()
        finally:
            conn.close()

    def subjects(self, kind: str) -> Dict[str, float]:
        return {s: ts for (s, k, _), ts in self._facts.items() if k == kind}

    def values(self, subject: str, kind: str) -> List[str]:
        return sorted(v for (s, k, v) in self._facts if s == subject and k == kind)


class BaselineDetector(BaseDetector):
    """
    Learn, then flag change.

    For ``learning_seconds`` after the baseline is first created (default a
    day) everything is recorded silently.  After that:

    * a program (by executable path) that has never reached the internet
      raises ``HOST-NEW-PROGRAM``;
    * a non-browser app that has been known for longer than the learning
      window contacting a new country raises ``BASELINE-NEW-COUNTRY``.
    """

    def __init__(self, store: BaselineStore, learning_seconds: float = 86400.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self.learning_seconds = learning_seconds
        self._clock = clock

    @property
    def name(self) -> str:
        return "baseline"

    @property
    def learning(self) -> bool:
        return self._clock() - self.store.created < self.learning_seconds

    def values(self, subject: str, kind: str) -> List[str]:
        return self.store.values(subject, kind)

    def first_seen(self, subject: str, kind: str, value: str = "") -> Optional[float]:
        return self.store.first_seen(subject, kind, value)

    def status(self) -> Dict[str, Any]:
        now = self._clock()
        return {
            "learning": self.learning,
            "learning_ends": self.store.created + self.learning_seconds,
            "created": self.store.created,
            "programs": len(self.store.subjects("program")),
            "apps": len(self.store.subjects("app")),
            "now": now,
        }

    def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
        context = layer7.get("context") or {}
        if not _outbound_public(meta, context):
            return
        now = self._clock()
        learning = now - self.store.created < self.learning_seconds
        exe = context.get("exe")
        app = context.get("app")

        if exe and self.store.add(exe, "program", ts=now) and not learning \
                and not context.get("system_process"):
            sig = context.get("signature")
            untrusted = sig in codesign.UNTRUSTED
            name = app or exe.rsplit("/", 1)[-1]
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.MEDIUM if untrusted else Severity.LOW,
                message=f"New program on the network: {name} used the internet for the first time",
                src_ip=meta.get("src_ip"), dst_ip=meta.get("dst_ip"),
                dst_port=meta.get("dst_port"), protocol=meta.get("protocol"),
                rule_id="HOST-NEW-PROGRAM",
                tags=["baseline", "new_program"],
                confidence=0.6,
                evidence={"exe": exe, "signature": sig, "first_destination": context.get("remote_host") or meta.get("dst_ip")},
            )

        if not app or app in BROWSERS or app == "Unattributed":
            return
        app_first = self.store.first_seen(app, "app")
        if app_first is None:
            self.store.add(app, "app", ts=now)
            app_first = now
        country = context.get("country")
        if not country:
            return
        if self.store.add(app, "country", country, ts=now):
            mature = now - app_first >= self.learning_seconds
            if not learning and mature:
                where = context.get("country_name") or country
                known = self.store.values(app, "country")
                yield Alert(
                    alert_type=AlertType.ANOMALY,
                    severity=Severity.LOW,
                    message=f"{app} contacted a server in {where} for the first time",
                    src_ip=meta.get("src_ip"), dst_ip=meta.get("dst_ip"),
                    dst_port=meta.get("dst_port"), protocol=meta.get("protocol"),
                    rule_id="BASELINE-NEW-COUNTRY",
                    tags=["baseline", "new_country"],
                    confidence=0.5,
                    evidence={"country": country, "country_name": context.get("country_name"),
                              "org": context.get("org"),
                              "usual_countries": [c for c in known if c != country][:12]},
                )


# ---------------------------------------------------------------------------
# "Likely C2" correlation
# ---------------------------------------------------------------------------

_SIGNAL_LABELS = {
    "beacon": "regular automated check-ins",
    "bare_ip": "talks to a bare IP that was never looked up in DNS",
    "intel": "the server is on a threat-intelligence blocklist",
    "untrusted_binary": "the program is unsigned or runs from a suspicious location",
    "new_program": "the program had never used the network before",
    "c2_infra": "the server is tagged as C2 / malware infrastructure by Shodan",
}
_NETWORK_SIGNALS = frozenset({"beacon", "intel", "c2_infra"})


class C2Correlator(BaseOutput):
    """
    Join independent signals per (program, server) into one CRITICAL alert.

    Args:
        emit:       ``Alert -> None``, normally ``AlertManager.add``.
        infra_tags: ``ip -> [shodan tags]`` from the lookup cache (optional).
        window:     How long a signal counts (default 6 h).
    """

    RULE = "HOST-C2-LIKELY"

    def __init__(self, emit: Callable[[Alert], Any],
                 infra_tags: Optional[Callable[[str], List[str]]] = None,
                 window: float = 6 * 3600) -> None:
        self._emit = emit
        self._infra = infra_tags
        self.window = window
        self._by_app: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._by_remote: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._pairs: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)  # app -> {(remote, port)}
        self._fired: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._busy = threading.local()

    def emit(self, alert: Alert) -> None:
        if alert.rule_id == self.RULE or getattr(self._busy, "on", False):
            return
        ctx = alert.context or {}
        app = ctx.get("exe") or ctx.get("app")
        remote = ctx.get("remote_ip") or (alert.dst_ip if ctx.get("direction") != "inbound" else alert.src_ip)
        tags = set(alert.tags or ())
        now = alert.timestamp or time.time()
        signals_app, signals_remote = [], []
        if "beaconing" in tags:
            signals_remote.append("beacon")
            if not (alert.evidence or {}).get("hostname_known", True):
                signals_remote.append("bare_ip")
        if alert.alert_type == AlertType.THREAT_INTEL:
            signals_remote.append("intel")
        if alert.rule_id == "HOST-PROCESS-RISK" and alert.severity >= Severity.MEDIUM:
            signals_app.append("untrusted_binary")
        if alert.rule_id == "HOST-NEW-PROGRAM":
            signals_app.append("new_program")
        if not (signals_app or signals_remote):
            return
        with self._lock:
            if app:
                for s in signals_app:
                    self._by_app[app][s] = now
            if remote:
                for s in signals_remote:
                    self._by_remote[remote][s] = now
            if app and remote:
                self._pairs[app].add((remote, str(alert.dst_port or "")))
            candidates = [(app, r, p) for r, p in self._pairs.get(app, ())] if app else []
            if remote and not app:
                candidates = [(None, remote, str(alert.dst_port or ""))]
        for cand_app, cand_remote, port in candidates:
            self._evaluate(cand_app, cand_remote, port, alert, now)

    def _signals(self, app: Optional[str], remote: str, now: float) -> Set[str]:
        out: Set[str] = set()
        for source in (self._by_app.get(app or "", {}), self._by_remote.get(remote, {})):
            out |= {s for s, ts in source.items() if now - ts <= self.window}
        if self._infra:
            try:
                infra = {t.lower() for t in self._infra(remote) or []}
            except Exception:  # noqa: BLE001
                infra = set()
            if infra & {"c2", "malware", "botnet"}:
                out.add("c2_infra")
        return out

    def _evaluate(self, app: Optional[str], remote: str, port: str, trigger: Alert, now: float) -> None:
        with self._lock:
            signals = self._signals(app, remote, now)
            if len(signals - {"bare_ip"}) < 2 or not signals & _NETWORK_SIGNALS:
                return
            key = (app or "", remote)
            if now - self._fired.get(key, 0) < self.window:
                return
            self._fired[key] = now
        ctx = trigger.context or {}
        name = ctx.get("app") or (app.rsplit("/", 1)[-1] if app else trigger.src_ip)
        host = ctx.get("remote_host") if ctx.get("remote_ip") == remote else None
        target = f"{host} ({remote})" if host else remote
        alert = Alert(
            alert_type=AlertType.CORRELATION,
            severity=Severity.CRITICAL,
            message=f"Likely command-and-control: {name} → {target}",
            src_ip=trigger.src_ip if trigger.src_ip != remote else trigger.dst_ip,
            dst_ip=remote,
            dst_port=int(port) if port.isdigit() else None,
            protocol=trigger.protocol,
            rule_id=self.RULE,
            mitre_technique="T1071",
            tags=["likely_c2", "c2", "correlation"],
            confidence=min(0.95, 0.5 + 0.15 * len(signals)),
            evidence={
                "signals": sorted(signals),
                "reasons": [_SIGNAL_LABELS[s] for s in sorted(signals)],
                "exe": app if app and app.startswith("/") else None,
            },
            context={**ctx, "remote_ip": remote, **({"remote_host": host} if host else {})},
        )
        self._busy.on = True
        try:
            self._emit(alert)
        finally:
            self._busy.on = False
