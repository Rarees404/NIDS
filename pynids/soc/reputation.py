"""
Reputation: what the outside world knows about an indicator, checked
automatically for the addresses, domains, URLs and program hashes behind
notable alerts.

It reuses the investigation workbench's sources (VirusTotal, AbuseIPDB,
AlienVault OTX, GreyNoise, URLhaus, ThreatFox, MalwareBazaar), its cache and
its per-minute rate limits, and adds what unattended use needs:

* **Privacy.**  A lookup tells a third party that this Mac is interested in
  an indicator.  Automatic checks follow ``lookups.mode`` (``manual`` switches
  them off), only cover alerts at or above ``lookups.min_severity``, never
  send private addresses or internal names, and send URLs without their query
  string.  Unattended, a source is only used once the user has stored an API
  key for it — adding the key is the consent to send that provider indicators
  (a manual check also uses the sources that work without a key).  File
  contents never leave the machine: only the SHA-256.
* **Quotas.**  At most ``max_auto_per_hour`` indicators an hour, each source
  kept under its free daily quota, and a source that fails or throttles is
  left alone for a while.
* **Escalation.**  When a trustworthy source calls an indicator malicious, a
  threat-intel alert is raised once, carrying the original alert's context,
  so it reaches notifications, incidents and (if enabled) auto-blocking.
"""
from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from ..alerts.incidents import remote_address
from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, AlertType, Severity
from .ioc import Ioc, classify, private_reason
from .sources import VERDICT_RANK

logger = logging.getLogger(__name__)

# Sources that give a verdict (the workbench's other sources describe an
# indicator — owner, DNS, certificates — without judging it).
REPUTATION_SOURCES: Tuple[str, ...] = (
    "virustotal", "abuseipdb", "otx", "greynoise", "urlhaus", "threatfox", "malwarebazaar",
)
# A "malicious" from one of these is enough to raise an alert.  OTX pulses and
# GreyNoise noise classifications include too much benign infrastructure to
# act on alone; they still count as a second opinion.
STRONG_SOURCES = frozenset({"virustotal", "abuseipdb", "urlhaus", "threatfox", "malwarebazaar"})
MODES = ("alerts", "always", "manual")
RULE_ID = "INTEL-REPUTATION"
_STOP: Any = object()
_SOURCE_PAUSE = 900.0     # seconds a failing source is skipped by automatic checks
_REALERT_AFTER = 7 * 86400
_RECHECK_AFTER = 3600.0   # an indicator is queued at most once an hour (answers are cached longer)
_HASH_TYPES = ("md5", "sha1", "sha256")


def normalise(kind: str, value: str) -> Optional[Ioc]:
    """The indicator as it is sent out and cached: validated, URLs without query or fragment."""
    ioc = classify(value or "")
    if ioc is None or (kind and ioc.type != kind):
        return None
    if ioc.type == "url":
        parts = urlsplit(ioc.value)
        if parts.query or parts.fragment:
            ioc = Ioc("url", urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")), ioc.original)
    return ioc


def _headline(result: Dict[str, Any]) -> str:
    for label, value in result.get("summary") or []:
        if isinstance(value, (list, dict)):
            continue
        return f"{label}: {value}"
    return result.get("message") or ""


class Reputation:
    """
    Args:
        workbench:  The investigation :class:`~pynids.soc.workbench.Workbench`.
        mode:       ``alerts`` / ``always`` / ``manual`` — what may be checked unasked.
        enabled:    False switches automatic checks off regardless of *mode*.
        sources:    Names of the sources to use (default: every reputation source).
        emit:       Callable receiving the escalation :class:`Alert` (``AlertManager.add``).
        hasher:     ``path -> sha256`` for program files.
        db_path:    Where the list of already-raised indicators is kept.
    """

    def __init__(self, workbench: Any, mode: str = "alerts", enabled: bool = True,
                 sources: Optional[List[str]] = None, emit: Optional[Callable[[Alert], Any]] = None,
                 hasher: Optional[Callable[[str], Optional[str]]] = None,
                 db_path: Optional[Path] = None, max_auto_per_hour: int = 60,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.workbench = workbench
        self.mode = mode if mode in MODES else "alerts"
        self.enabled = bool(enabled)
        wanted = [s for s in (sources or REPUTATION_SOURCES) if s in workbench.sources]
        self.source_names: Tuple[str, ...] = tuple(wanted)
        self.emit = emit
        self.hasher = hasher
        self.db_path = Path(db_path) if db_path else None
        self.max_auto_per_hour = max_auto_per_hour
        self._sleep = sleep
        self._lock = threading.Lock()
        self._queue: "queue.Queue[Any]" = queue.Queue(maxsize=500)
        self._queued: set = set()
        self._auto_times: List[float] = []
        self._day: Tuple[str, Dict[str, int]] = ("", {})
        self._paused_until: Dict[str, float] = {}
        self._hashes: Dict[str, Tuple[Tuple[int, int], Optional[str]]] = {}
        self._raised: Dict[Tuple[str, str], float] = {}
        self._recent: Dict[Tuple[str, str], float] = {}   # indicator → last automatic check
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="reputation")
        self.checked = 0
        self.flagged = 0
        self._init_db()

    # --- configuration ----------------------------------------------------

    @property
    def automatic(self) -> bool:
        return self.enabled and self.mode != "manual"

    def _configured(self, src: Any) -> bool:
        return not src.key or src.key_optional or self.workbench.keys.configured(src.key)

    def _has_key(self, src: Any) -> bool:
        return bool(src.key) and self.workbench.keys.configured(src.key)

    def sources_for(self, ioc: Ioc, auto: bool = False) -> List[Any]:
        out = []
        now = time.time()
        for name in self.source_names:
            src = self.workbench.sources[name]
            if not src.supports(ioc) or src.active or not self._configured(src):
                continue
            if auto and (not self._has_key(src) or self._paused_until.get(name, 0) > now
                         or self._over_quota(src)):
                continue
            out.append(src)
        return out

    def status(self) -> Dict[str, Any]:
        """What the dashboard shows about automatic checks."""
        rows = []
        for name in self.source_names:
            src = self.workbench.sources[name]
            rows.append({"name": name, "label": src.label, "types": list(src.types),
                         "needs_key": bool(src.key) and not src.key_optional,
                         "configured": self._configured(src), "key": src.key,
                         "has_key": self._has_key(src), "automatic": self.automatic and self._has_key(src),
                         "paused": self._paused_until.get(name, 0) > time.time(),
                         "used_today": self._used(name), "per_day": src.per_day})
        return {"automatic": self.automatic, "mode": self.mode, "enabled": self.enabled,
                "sources": rows, "checked": self.checked, "flagged": self.flagged,
                "queued": self._queue.qsize(), "max_auto_per_hour": self.max_auto_per_hour}

    # --- quotas -----------------------------------------------------------

    def _used(self, name: str) -> int:
        day, counts = self._day
        return counts.get(name, 0) if day == time.strftime("%Y-%m-%d", time.gmtime()) else 0

    def _count(self, name: str) -> None:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock:
            if self._day[0] != today:
                self._day = (today, {})
            self._day[1][name] = self._day[1].get(name, 0) + 1

    def _over_quota(self, src: Any) -> bool:
        # Automatic checks use at most 80% of a free daily quota; the rest is the analyst's.
        return bool(src.per_day) and self._used(src.name) >= int(src.per_day * 0.8)

    # --- storage of raised indicators -------------------------------------

    def _init_db(self) -> None:
        if not self.db_path:
            return
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.execute("CREATE TABLE IF NOT EXISTS reputation_alerts "
                         "(kind TEXT, value TEXT, raised REAL, PRIMARY KEY (kind, value))")
            conn.commit()
            for kind, value, raised in conn.execute("SELECT kind, value, raised FROM reputation_alerts"):
                self._raised[(kind, value)] = raised
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("reputation: state unavailable: %s", exc)
            self.db_path = None

    def _mark_raised(self, ioc: Ioc) -> bool:
        """True the first time (in a week) an indicator is raised."""
        now = time.time()
        with self._lock:
            if now - self._raised.get((ioc.type, ioc.value), 0) < _REALERT_AFTER:
                return False
            self._raised[(ioc.type, ioc.value)] = now
        if self.db_path:
            try:
                conn = sqlite3.connect(str(self.db_path), timeout=5)
                conn.execute("INSERT OR REPLACE INTO reputation_alerts VALUES (?, ?, ?)",
                             (ioc.type, ioc.value, now))
                conn.commit()
                conn.close()
            except sqlite3.Error as exc:
                logger.debug("reputation: could not record %s: %s", ioc.value, exc)
        return True

    # --- reading ----------------------------------------------------------

    def summary(self, kind: str, value: str, results: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """The combined verdict from what is already known — never a new request."""
        ioc = normalise(kind, value)
        if ioc is None:
            return {"type": kind, "value": value, "verdict": "unknown", "sources": [], "checked": 0,
                    "error": "not a valid indicator"}
        reason = private_reason(ioc)
        if reason:
            return {"type": ioc.type, "value": ioc.value, "verdict": "unknown", "sources": [],
                    "checked": 0, "private": reason}
        rows: List[Dict[str, Any]] = []
        missing: List[Dict[str, Any]] = []
        by_name = {r.get("source"): r for r in results or []}
        for name in self.source_names:
            src = self.workbench.sources[name]
            if not src.supports(ioc) or src.active:
                continue
            if not self._configured(src):
                missing.append({"name": name, "label": src.label, "key": src.key})
                continue
            r = by_name.get(name) or self.workbench.stored(name, ioc.type, ioc.value)
            if r is None:
                rows.append({"source": name, "label": src.label, "status": "pending", "verdict": "unknown"})
                continue
            rows.append({"source": name, "label": src.label, "status": r.get("status"),
                         "verdict": r.get("verdict") or "unknown", "headline": _headline(r),
                         "message": r.get("message") or "", "tags": (r.get("tags") or [])[:6],
                         "fetched": r.get("fetched"), "retry_after": r.get("retry_after")})
        answered = [r for r in rows if r["status"] in ("ok", "not_found")]
        verdict = "unknown"
        for r in answered:
            if r["status"] == "ok" and VERDICT_RANK.get(r["verdict"], 0) > VERDICT_RANK[verdict]:
                verdict = r["verdict"]
        return {
            "type": ioc.type, "value": ioc.value, "verdict": verdict,
            "checked": len(answered),
            "flagged_by": [r["label"] for r in answered if r["verdict"] in ("malicious", "suspicious")],
            "malicious_by": [r["source"] for r in answered if r["verdict"] == "malicious"],
            "sources": rows, "missing_keys": missing,
            "fetched": max([r["fetched"] for r in answered if r.get("fetched")] or [None],
                           key=lambda v: v or 0),
        }

    # --- checking ---------------------------------------------------------

    def check(self, kind: str, value: str, refresh: bool = False, timeout: float = 25.0) -> Dict[str, Any]:
        """Ask every usable source now (in parallel) and return the combined verdict."""
        ioc = normalise(kind, value)
        if ioc is None or private_reason(ioc):
            return self.summary(kind, value)
        sources = self.sources_for(ioc)
        futures = {self._pool.submit(self._ask, s, ioc, refresh, True): s for s in sources}
        wait(list(futures), timeout=timeout)
        results = [f.result() for f in futures if f.done() and not f.exception()]
        return self.summary(ioc.type, ioc.value, results)

    def _ask(self, src: Any, ioc: Ioc, refresh: bool, remember: bool) -> Dict[str, Any]:
        result = self.workbench.lookup(src.name, ioc.type, ioc.value, refresh=refresh, remember=remember)
        if not result.get("cached") and result.get("status") in ("ok", "not_found", "error"):
            self._count(src.name)
        return {**result, "source": src.name}

    def _check_auto(self, ioc: Ioc) -> Dict[str, Any]:
        """One source after another, waiting out per-minute limits; failing sources are paused."""
        results = []
        for src in self.sources_for(ioc, auto=True):
            result: Dict[str, Any] = {}
            for _ in range(4):
                result = self._ask(src, ioc, False, False)
                if result.get("status") != "rate_limited" or self._stopping.is_set():
                    break
                self._sleep(min(20.0, float(result.get("retry_after") or 15)))
            if result.get("status") in ("error", "rate_limited", "needs_key"):
                self._paused_until[src.name] = time.time() + _SOURCE_PAUSE
                logger.debug("reputation: pausing %s: %s", src.name, result.get("message"))
            results.append(result)
        self.checked += 1
        return self.summary(ioc.type, ioc.value, results)

    # --- automatic checks -------------------------------------------------

    def start(self) -> "Reputation":
        if self.automatic and self._thread is None:
            self._stopping.clear()
            self._thread = threading.Thread(target=self._run, name="reputation", daemon=True)
            self._thread.start()
        return self

    def stop(self, timeout: float = 5.0) -> None:
        thread, self._thread = self._thread, None
        self._stopping.set()
        if thread is not None:
            try:
                self._queue.put_nowait(_STOP)
            except queue.Full:
                pass
            thread.join(timeout)
        self._pool.shutdown(wait=False)

    def enqueue(self, kind: str, value: str, origin: Optional[Alert] = None) -> bool:
        """Queue an indicator for an automatic check.  ``kind`` may be ``"exe"`` (a program path)."""
        if not self.automatic:
            return False
        if kind == "exe":
            key = ("exe", value)
        else:
            ioc = normalise(kind, value)
            if ioc is None or private_reason(ioc) or not self.sources_for(ioc, auto=True):
                return False
            key = (ioc.type, ioc.value)
        now = time.time()
        with self._lock:
            if (key in self._queued or now - self._raised.get(key, 0) < _REALERT_AFTER
                    or now - self._recent.get(key, 0) < _RECHECK_AFTER):
                return False
            self._auto_times = [t for t in self._auto_times if now - t < 3600]
            if len(self._auto_times) >= self.max_auto_per_hour:
                return False
            self._queued.add(key)
            self._auto_times.append(now)
            if len(self._recent) > 20_000:
                self._recent = {k: t for k, t in self._recent.items() if now - t < _RECHECK_AFTER}
            self._recent[key] = now
        try:
            self._queue.put_nowait((key, origin))
        except queue.Full:
            with self._lock:
                self._queued.discard(key)
            return False
        return True

    def _run(self) -> None:
        while not self._stopping.is_set():
            item = self._queue.get()
            if item is _STOP or self._stopping.is_set():
                break
            key, origin = item
            try:
                self.process(key[0], key[1], origin)
            except Exception as exc:  # noqa: BLE001 — one bad indicator must not end the worker
                logger.debug("reputation: check of %s failed: %s", key[1], exc)
            finally:
                with self._lock:
                    self._queued.discard(key)

    def process(self, kind: str, value: str, origin: Optional[Alert] = None) -> Optional[Dict[str, Any]]:
        """Check one queued indicator and raise an alert when it is known to be malicious."""
        program = None
        if kind == "exe":
            program = value
            sha = self._hash(value)
            if not sha:
                return None
            kind, value = "sha256", sha
        ioc = normalise(kind, value)
        if ioc is None or private_reason(ioc):
            return None
        # Everything fresh in the cache?  Then no request is made at all.
        summary = self._check_auto(ioc)
        self._escalate(ioc, summary, origin, program)
        return summary

    def _hash(self, path: str) -> Optional[str]:
        if self.hasher is None:
            return None
        try:
            st = Path(path).stat()
        except OSError:
            return None
        stamp = (st.st_mtime_ns, st.st_size)
        hit = self._hashes.get(path)
        if hit and hit[0] == stamp:
            return hit[1]
        try:
            sha = self.hasher(path)
        except Exception as exc:  # noqa: BLE001
            logger.debug("reputation: could not hash %s: %s", path, exc)
            sha = None
        if len(self._hashes) > 2000:
            self._hashes.clear()
        self._hashes[path] = (stamp, sha)
        return sha

    def _escalate(self, ioc: Ioc, summary: Dict[str, Any], origin: Optional[Alert],
                  program: Optional[str]) -> Optional[Alert]:
        malicious = summary.get("malicious_by") or []
        if self.emit is None or not STRONG_SOURCES.intersection(malicious):
            return None
        if not self._mark_raised(ioc):
            return None
        self.flagged += 1
        rows = [r for r in summary["sources"] if r["verdict"] == "malicious"]
        names = ", ".join(r["label"] for r in rows)
        detail = next((r["headline"] for r in rows if r.get("headline")), "")
        if program:
            what = f"Program {program.rsplit('/', 1)[-1]} is known malware"
        elif ioc.type in _HASH_TYPES:
            what = f"File {ioc.value[:16]}… is known malware"
        else:
            what = f"{ioc.value} is known to be malicious"
        ctx = dict(origin.context) if origin is not None else {}
        alert = Alert(
            alert_type=AlertType.THREAT_INTEL,
            severity=Severity.CRITICAL if len(malicious) >= 2 else Severity.HIGH,
            message=f"{what} ({names}{': ' + detail if detail else ''})"[:300],
            src_ip=origin.src_ip if origin else None,
            dst_ip=origin.dst_ip if origin else None,
            src_port=origin.src_port if origin else None,
            dst_port=origin.dst_port if origin else None,
            protocol=origin.protocol if origin else None,
            rule_id=RULE_ID,
            flow_id=origin.flow_id if origin else None,
            confidence=0.95 if len(malicious) >= 2 else 0.8,
            tags=["threat_intel", "reputation", ioc.type],
            mitre_technique=(origin.mitre_technique if origin else None) or ("T1204.002" if program else "T1071"),
            evidence={
                "indicator": ioc.value, "indicator_type": ioc.type, "program": program,
                "verdict": summary["verdict"], "flagged_by": summary.get("flagged_by"),
                "sources": [{k: r.get(k) for k in ("source", "label", "verdict", "headline", "tags")}
                            for r in summary["sources"] if r["status"] == "ok"],
                "triggered_by": {"alert_id": origin.alert_id, "rule_id": origin.rule_id,
                                 "message": origin.message} if origin else None,
            },
            context=ctx,
        )
        try:
            self.emit(alert)
        except Exception as exc:  # noqa: BLE001
            logger.error("reputation: could not raise alert for %s: %s", ioc.value, exc)
        return alert


class ReputationOutput(BaseOutput):
    """Alert output: queue the indicators behind notable alerts for a reputation check."""

    def __init__(self, reputation: Reputation, min_severity: Severity = Severity.MEDIUM) -> None:
        self.reputation = reputation
        self.min_severity = min_severity

    def emit(self, alert: Alert) -> None:
        rep = self.reputation
        if not rep.automatic or "reputation" in (alert.tags or ()):
            return
        if (alert.rule_id or "").startswith("STEALTH-"):
            return
        if rep.mode == "alerts" and alert.severity < self.min_severity:
            return
        ctx = alert.context or {}
        ev = alert.evidence or {}
        l7 = ev.get("layer7") if isinstance(ev.get("layer7"), dict) else {}

        def sub(proto: str, field: str) -> Any:
            part = l7.get(proto)
            return part.get(field) if isinstance(part, dict) else None

        remote = remote_address({"context": ctx, "src_ip": alert.src_ip, "dst_ip": alert.dst_ip})
        if remote:
            rep.enqueue("ipv6" if ":" in str(remote) else "ipv4", str(remote), alert)
        names = {sub("dns", "query_name"), sub("tls", "sni"), sub("quic", "sni"), ctx.get("remote_host"),
                 ev.get("query_name"), ev.get("sni"), ev.get("domain")}
        host = sub("http", "host") or ev.get("host")
        if isinstance(host, str):
            names.add(host.split(":")[0])
            uri = sub("http", "uri")
            if isinstance(uri, str) and uri.startswith("/") and sub("http", "direction") == "request":
                rep.enqueue("url", f"http://{host}{uri}", alert)
        for name in names:
            if isinstance(name, str) and name:
                rep.enqueue("domain", name.strip().rstrip(".").lower(), alert)
        # The program behind the connection: its hash, never the file.
        exe = ctx.get("exe")
        if exe and ctx.get("signature") not in ("apple", "app_store"):
            rep.enqueue("exe", str(exe), alert)
