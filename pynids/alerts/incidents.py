"""
Incidents: alerts that belong to the same story, kept together.

One port scan, one beaconing implant or one phishing page rarely raises a
single alert.  The tracker files every security-relevant alert under an
*incident*: all alerts about the same subject (a remote address, a domain,
a program on this Mac) with no pause longer than ``gap`` seconds between
them.  The analyst then reads one timeline instead of forty rows.

Storage sits next to the alerts in the same SQLite file:

``incidents``        one row per incident: subject, first / last alert,
                     worst severity, triage status and note
``incident_alerts``  which alert belongs to which incident

Everything else (ATT&CK tactics touched, rules that fired, apps, indicators)
is worked out from the member alerts when an incident is read, so it can
never drift from the evidence.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .classify import classify, detector_label
from .guide import describe
from .manager import BaseOutput
from .mitre import TACTICS, technique
from .model import Alert

logger = logging.getLogger(__name__)

# Alert kinds that describe an attack or a risk on this machine.  Privacy
# telemetry (trackers, QUIC, DoH …) only joins an incident when it is serious.
SECURITY_KINDS = frozenset({"threat", "attack", "host", "localhost"})
STATUSES = ("open", "acknowledged", "closed")
_SEV_NAME = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_SEV_NUM = {v: k for k, v in _SEV_NAME.items()}
_HOST_TAGS = frozenset({"host_risk", "new_program", "baseline"})
MAX_ALERTS_PER_INCIDENT = 1000   # alerts returned for one incident
_MAX_ACTIVE = 5000               # subjects remembered for grouping

_DDL = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id      TEXT PRIMARY KEY,
    entity_type      TEXT NOT NULL,
    entity           TEXT NOT NULL,
    label            TEXT,
    first_seen       REAL NOT NULL,
    last_seen        REAL NOT NULL,
    alert_count      INTEGER NOT NULL DEFAULT 0,
    severity_numeric INTEGER NOT NULL DEFAULT 1,
    status           TEXT NOT NULL DEFAULT 'open',
    note             TEXT NOT NULL DEFAULT '',
    updated          REAL
);
CREATE INDEX IF NOT EXISTS idx_incidents_last ON incidents (last_seen);
CREATE TABLE IF NOT EXISTS incident_alerts (
    alert_id    TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    timestamp   REAL
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc ON incident_alerts (incident_id);
CREATE TABLE IF NOT EXISTS incident_meta (key TEXT PRIMARY KEY, value TEXT);
"""

_UPSERT = """
INSERT INTO incidents (incident_id, entity_type, entity, label, first_seen, last_seen,
                       alert_count, severity_numeric, updated)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT (incident_id) DO UPDATE SET
    last_seen = MAX(last_seen, excluded.last_seen),
    first_seen = MIN(first_seen, excluded.first_seen),
    alert_count = alert_count + 1,
    severity_numeric = MAX(severity_numeric, excluded.severity_numeric),
    label = COALESCE(excluded.label, label)
"""

_ALERT_COLUMNS = ("alert_id, timestamp, alert_type, severity, severity_numeric, message, src_ip, dst_ip, "
                  "src_port, dst_port, protocol, rule_id, flow_id, confidence, tags, mitre_technique, "
                  "evidence, context")


# ---------------------------------------------------------------------------
# What an alert is about
# ---------------------------------------------------------------------------

def _dns_name(alert: Dict[str, Any]) -> Optional[str]:
    ev = alert.get("evidence") or {}
    l7 = ev.get("layer7") if isinstance(ev.get("layer7"), dict) else {}
    dns = l7.get("dns") if isinstance(l7.get("dns"), dict) else {}
    name = dns.get("query_name") or ev.get("query_name") or ev.get("domain")
    if not isinstance(name, str) or "." not in name:
        return None
    return name.strip().rstrip(".").lower() or None


def _registered(name: str) -> str:
    try:
        from ..soc.sources.free import registered_domain
        return registered_domain(name) or name
    except Exception:  # noqa: BLE001 — grouping must never fail on an odd name
        return name


def _is_public(ip: Any) -> bool:
    try:
        return ipaddress.ip_address(str(ip).split("%")[0]).is_global
    except ValueError:
        return False


def remote_address(alert: Dict[str, Any]) -> Optional[str]:
    """The address on the other side of an alert: the one to group by, look up and block.

    Enrichment knows it for traffic to or from this machine.  For traffic that only
    passes by (a mirror port, a bridged VM) or was never enriched, it is the internet
    side when there is exactly one, otherwise the sender.
    """
    ctx = alert.get("context") or {}
    src, dst = alert.get("src_ip"), alert.get("dst_ip")
    direction = ctx.get("direction")
    if direction == "inbound":
        return str(ctx.get("remote_ip") or src or "") or None
    if direction == "outbound":
        return str(ctx.get("remote_ip") or dst or "") or None
    if src and dst and _is_public(dst) and not _is_public(src):
        return str(dst)
    return str(src or dst or ctx.get("remote_ip") or "") or None


def entity_of(alert: Dict[str, Any], kind: Optional[str] = None) -> Optional[Tuple[str, str, Optional[str]]]:
    """``(type, value, label)`` of the subject an alert is about, or None.

    * a finding about a program on this Mac → the program
    * a DNS-based detection → the registered domain that was looked up (the
      packet's destination is only the resolver)
    * anything else → the remote address, labelled with its hostname
    """
    ctx = alert.get("context") or {}
    tags = set(alert.get("tags") or ())
    kind = kind or alert.get("kind") or classify(alert)
    if kind == "host" and tags & _HOST_TAGS and (ctx.get("exe") or ctx.get("app")):
        return "program", str(ctx.get("exe") or ctx.get("app")), ctx.get("app")
    name = _dns_name(alert)
    if name:
        return "domain", _registered(name), None
    ip = remote_address(alert)
    if ip:
        return "ip", ip, ctx.get("remote_host") if ip == ctx.get("remote_ip") else None
    if ctx.get("app"):
        return "program", str(ctx.get("exe") or ctx["app"]), ctx.get("app")
    return None


def eligible(alert: Dict[str, Any], kind: str) -> bool:
    """Does this alert belong in an incident at all?"""
    return kind in SECURITY_KINDS or int(alert.get("severity_numeric") or 0) >= 3


def parse_alert_row(row: Any) -> Dict[str, Any]:
    """A row of the ``alerts`` table as the alert dict every UI uses."""
    d = dict(row)
    for key in ("tags", "evidence", "context"):
        try:
            d[key] = json.loads(d.get(key) or ("[]" if key == "tags" else "{}"))
        except (TypeError, ValueError):
            d[key] = [] if key == "tags" else {}
    d["kind"] = classify(d)
    d["about"] = describe(d)
    d["mitre"] = technique(d.get("mitre_technique"))
    return d


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

def _candidates(alert: Dict[str, Any]) -> Iterable[Tuple[str, Any]]:
    ctx = alert.get("context") or {}
    ev = alert.get("evidence") or {}
    l7 = ev.get("layer7") if isinstance(ev.get("layer7"), dict) else {}
    http = l7.get("http") if isinstance(l7.get("http"), dict) else {}
    yield "remote address", ctx.get("remote_ip")
    yield "source", alert.get("src_ip")
    yield "destination", alert.get("dst_ip")
    yield "hostname", ctx.get("remote_host")
    for proto in ("tls", "quic"):
        yield "TLS server name", (l7.get(proto) or {}).get("sni") if isinstance(l7.get(proto), dict) else None
    yield "DNS query", _dns_name(alert)
    host = http.get("host") or ev.get("host")
    yield "HTTP host", str(host).split(":")[0] if host else None
    if host and http.get("uri") and str(http.get("uri")).startswith("/"):
        yield "URL", f"http://{host}{http['uri']}"
    for key in ("sni", "url", "indicator", "leaked_ip", "resolver"):
        yield key.replace("_", " "), ev.get(key)
    for key in ("sha256", "sha1", "md5"):
        yield "file hash", ev.get(key) or ctx.get(key)


def extract_iocs(alerts: Iterable[Dict[str, Any]], limit: int = 60) -> List[Dict[str, Any]]:
    """Distinct indicators mentioned by *alerts*: public ones first, most seen first."""
    from ..soc.ioc import classify as classify_ioc, private_reason

    found: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for alert in alerts:
        seen_here = set()
        for role, raw in _candidates(alert):
            if not raw or not isinstance(raw, (str, int)):
                continue
            ioc = classify_ioc(str(raw))
            if ioc is None or ioc.type in ("email", "asn", "cve"):
                continue
            key = (ioc.type, ioc.value)
            if key in seen_here:
                continue
            seen_here.add(key)
            item = found.get(key)
            if item is None:
                reason = private_reason(ioc)
                item = found[key] = {"type": ioc.type, "value": ioc.value, "role": role, "count": 0,
                                     "public": reason is None, "private_reason": reason}
            item["count"] += 1
    out = sorted(found.values(), key=lambda i: (not i["public"], -i["count"], i["value"]))
    return out[:limit]


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def _top(counter: Dict[str, int], n: int = 8) -> List[str]:
    return [k for k, _ in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def summarise(row: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The list / header view of one incident, computed from its member alerts.

    *alerts* need ``timestamp, severity, severity_numeric, rule_id, mitre_technique,
    message, tags, context``; they may be an empty list (alerts still buffered).
    """
    techs: Dict[str, int] = {}
    rules: Dict[str, Dict[str, Any]] = {}
    apps: Dict[str, int] = {}
    hosts: Dict[str, int] = {}
    countries: Dict[str, int] = {}
    kinds: Dict[str, int] = {}
    worst: Optional[Dict[str, Any]] = None
    intel = False
    for a in alerts:
        ctx = a.get("context") or {}
        # A correlation alert sums up the others; its own technique would only add noise.
        if a.get("mitre_technique") and a.get("alert_type") != "correlation":
            tid = str(a["mitre_technique"]).upper()
            techs[tid] = techs.get(tid, 0) + 1
        name = a.get("rule_id") or detector_label(a.get("tags") or (), str(a.get("alert_type") or "other"))
        rule = rules.setdefault(name, {"id": name, "count": 0, "severity_numeric": 0, "example": ""})
        rule["count"] += 1
        sev = int(a.get("severity_numeric") or _SEV_NUM.get(str(a.get("severity")), 1))
        if sev >= rule["severity_numeric"]:
            rule["severity_numeric"], rule["example"] = sev, a.get("message") or ""
        for bucket, value in ((apps, ctx.get("app")), (hosts, ctx.get("remote_host")),
                              (countries, ctx.get("country"))):
            if value:
                bucket[str(value)] = bucket.get(str(value), 0) + 1
        kind = a.get("kind") or classify(a)
        kinds[kind] = kinds.get(kind, 0) + 1
        intel = intel or a.get("alert_type") == "threat_intel"
        if worst is None or (sev, a.get("timestamp") or 0) >= (
                int(worst.get("severity_numeric") or 0), worst.get("timestamp") or 0):
            worst = {**a, "severity_numeric": sev}

    technique_rows = []
    tactic_counts: Dict[str, int] = {}
    for tid, count in techs.items():
        info = technique(tid) or {"id": tid, "name": None, "tactic": None, "url": None}
        technique_rows.append({**info, "count": count})
        tactic = info.get("tactic") or "Other"
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + count
    order = {name: i for i, name in enumerate(TACTICS)}
    tactics = sorted(tactic_counts, key=lambda t: order.get(t, 99))
    technique_rows.sort(key=lambda t: (order.get(t.get("tactic") or "", 99), -t["count"]))

    sev_num = max([int(row.get("severity_numeric") or 1)] + [r["severity_numeric"] for r in rules.values()])
    count = len(alerts) or int(row.get("alert_count") or 0)
    first = min([a["timestamp"] for a in alerts if a.get("timestamp")] or [row.get("first_seen") or 0])
    last = max([a["timestamp"] for a in alerts if a.get("timestamp")] or [row.get("last_seen") or 0])
    # Priority: how bad the worst alert is, then how much of a story there is.
    score = {1: 10, 2: 35, 3: 65, 4: 88}[sev_num]
    score += min(6, max(0, len(rules) - 1) * 2) + min(6, max(0, len([t for t in tactics if t != "Other"]) - 1) * 3)
    score += 4 if intel else 0
    label = row.get("label")
    return {
        "incident_id": row["incident_id"],
        "status": row.get("status") or "open",
        "note": row.get("note") or "",
        "updated": row.get("updated"),
        "entity": {"type": row["entity_type"], "value": row["entity"], "label": label},
        "title": (worst or {}).get("message") or f"Activity involving {label or row['entity']}",
        "severity": _SEV_NAME[sev_num],
        "severity_numeric": sev_num,
        "score": min(100, score),
        "alert_count": count,
        "first_seen": first,
        "last_seen": last,
        "duration": max(0.0, (last or 0) - (first or 0)),
        "tactics": tactics,
        "techniques": technique_rows,
        "rules": sorted(({**r, "severity": _SEV_NAME.get(r["severity_numeric"], "LOW")} for r in rules.values()),
                        key=lambda r: (-r["severity_numeric"], -r["count"])),
        "kinds": _top(kinds),
        "apps": _top(apps),
        "hosts": _top(hosts),
        "countries": _top(countries),
        "threat_intel": intel,
    }


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class IncidentTracker(BaseOutput):
    """Alert output that files alerts under incidents, and the read side of the API.

    Args:
        db_path:      The alerts database (``None`` keeps everything in a private
                      in-memory database — for tests and ``pynids live``).
        gap:          Seconds of silence after which the next alert about the
                      same subject opens a new incident.
        before_read:  Called before every read, e.g. to flush buffered alerts so
                      a new incident never shows up without its alerts.
    """

    def __init__(self, db_path: Optional[Path] = None, gap: float = 1800.0,
                 before_read: Optional[Callable[[], None]] = None, flush_interval: float = 1.0) -> None:
        self.gap = float(gap)
        self.before_read = before_read
        self.flush_interval = flush_interval
        self._lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else None
        target = str(db_path) if db_path else ":memory:"
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(target, check_same_thread=False, timeout=5)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=5000")
        if db_path:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_DDL)
        self._conn.commit()
        # subject → [incident_id, last_seen]
        self._active: Dict[Tuple[str, str], List[Any]] = {}
        self._pending: List[Tuple[str, tuple]] = []
        self._last_flush = time.monotonic()
        self._load_active()

    # --- write side -------------------------------------------------------

    def _load_active(self) -> None:
        cutoff = time.time() - self.gap
        try:
            rows = self._conn.execute(
                "SELECT incident_id, entity_type, entity, last_seen FROM incidents "
                "WHERE last_seen >= ? AND status != 'closed'", (cutoff,)).fetchall()
        except sqlite3.Error as exc:
            logger.debug("incidents: could not load open incidents: %s", exc)
            return
        for r in rows:
            self._active[(r["entity_type"], r["entity"])] = [r["incident_id"], r["last_seen"]]

    def emit(self, alert: Alert) -> None:
        d = alert.to_dict()
        kind = classify(alert)
        if not eligible(d, kind):
            return
        entity = entity_of(d, kind)
        if entity is None:
            return
        with self._lock:
            self._assign(self._active, d, entity)
            if time.monotonic() - self._last_flush >= self.flush_interval or len(self._pending) >= 200:
                self._flush()

    def _assign(self, active: Dict[Tuple[str, str], List[Any]], d: Dict[str, Any],
                entity: Tuple[str, str, Optional[str]]) -> str:
        etype, value, label = entity
        ts = float(d.get("timestamp") or time.time())
        slot = active.get((etype, value))
        if slot is not None and ts - slot[1] <= self.gap:
            slot[1] = max(slot[1], ts)
        else:
            digest = hashlib.sha1(f"{etype}|{value}|{d.get('alert_id')}".encode()).hexdigest()[:12]
            slot = active[(etype, value)] = [f"INC-{digest}", ts]
            if len(active) > _MAX_ACTIVE:
                for key in sorted(active, key=lambda k: active[k][1])[:_MAX_ACTIVE // 10]:
                    del active[key]
        incident_id = slot[0]
        sev = int(d.get("severity_numeric") or 1)
        self._pending.append((_UPSERT, (incident_id, etype, value, label, ts, ts, sev, ts)))
        self._pending.append(("INSERT OR IGNORE INTO incident_alerts VALUES (?, ?, ?)",
                              (d.get("alert_id"), incident_id, ts)))
        return incident_id

    def flush(self) -> None:
        with self._lock:
            self._flush()

    def _flush(self) -> None:
        self._last_flush = time.monotonic()
        if not self._pending:
            return
        try:
            for sql, params in self._pending:
                self._conn.execute(sql, params)
            self._conn.commit()
            self._pending.clear()
        except sqlite3.OperationalError as exc:  # locked / busy: retry on the next flush
            self._rollback()
            logger.debug("incidents: flush postponed: %s", exc)
            if len(self._pending) > 20_000:
                del self._pending[:len(self._pending) - 20_000]
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("incidents: dropping %d buffered writes: %s", len(self._pending), exc)
            self._pending.clear()

    def _rollback(self) -> None:
        try:
            self._conn.rollback()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        self.flush()
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def backfill(self) -> int:
        """File alerts stored before incidents existed.  Runs once per database."""
        if self.db_path is None:
            return 0
        with self._lock:
            try:
                done = self._conn.execute("SELECT 1 FROM incident_meta WHERE key = 'backfilled'").fetchone()
                has_alerts = self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts'").fetchone()
            except sqlite3.Error:
                return 0
            if done or not has_alerts:
                return 0
        filed = 0
        active: Dict[Tuple[str, str], List[Any]] = {}
        try:
            reader = sqlite3.connect(str(self.db_path), timeout=5)
            reader.row_factory = sqlite3.Row
            cursor = reader.execute(
                f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE alert_id NOT IN "
                "(SELECT alert_id FROM incident_alerts) ORDER BY timestamp")
            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                with self._lock:
                    for row in rows:
                        d = dict(row)
                        for key in ("tags", "evidence", "context"):
                            try:
                                d[key] = json.loads(d.get(key) or ("[]" if key == "tags" else "{}"))
                            except (TypeError, ValueError):
                                d[key] = [] if key == "tags" else {}
                        kind = classify(d)
                        if not eligible(d, kind):
                            continue
                        entity = entity_of(d, kind)
                        if entity is not None:
                            self._assign(active, d, entity)
                            filed += 1
                    self._flush()
            reader.close()
        except sqlite3.Error as exc:
            logger.warning("incidents: backfill stopped: %s", exc)
            return filed
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO incident_meta VALUES ('backfilled', ?)", (str(time.time()),))
            self._conn.commit()
        if filed:
            logger.info("Filed %d stored alerts under incidents", filed)
        return filed

    def prune(self, max_age_days: float) -> int:
        """Forget incidents whose last alert is older than *max_age_days* (0 keeps everything)."""
        if not max_age_days or max_age_days <= 0:
            return 0
        cutoff = time.time() - max_age_days * 86400
        with self._lock:
            self._flush()
            try:
                self._conn.execute("DELETE FROM incident_alerts WHERE timestamp < ?", (cutoff,))
                cur = self._conn.execute("DELETE FROM incidents WHERE last_seen < ?", (cutoff,))
                self._conn.commit()
                return cur.rowcount
            except sqlite3.Error as exc:
                self._rollback()
                logger.error("incidents: prune failed: %s", exc)
                return 0

    # --- read side --------------------------------------------------------

    def _prepare_read(self) -> None:
        if self.before_read is not None:
            try:
                self.before_read()
            except Exception as exc:  # noqa: BLE001
                logger.debug("incidents: before_read failed: %s", exc)
        self._flush()

    def _has_alerts_table(self) -> bool:
        return bool(self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts'").fetchone())

    def _members(self, ids: List[str], columns: str, per_incident: Optional[int] = None) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {i: [] for i in ids}
        if not ids or not self._has_alerts_table():
            return out
        for start in range(0, len(ids), 400):
            chunk = ids[start:start + 400]
            marks = ",".join("?" * len(chunk))
            rows = self._conn.execute(
                f"SELECT ia.incident_id AS incident_id, {columns} FROM incident_alerts ia "
                f"JOIN alerts a ON a.alert_id = ia.alert_id WHERE ia.incident_id IN ({marks}) "
                "ORDER BY a.timestamp", chunk).fetchall()
            for r in rows:
                bucket = out[r["incident_id"]]
                if per_incident is None or len(bucket) < per_incident:
                    bucket.append(dict(r))
        return out

    def list(self, since: Optional[float] = None, until: Optional[float] = None,
             status: Optional[str] = None, min_severity: str = "LOW", tactic: Optional[str] = None,
             technique_id: Optional[str] = None, rule: Optional[str] = None,
             entity: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Incidents with activity in the window, most urgent first."""
        clauses, params = [], []
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(since)
        if until is not None:
            clauses.append("first_seen < ?")
            params.append(until)
        if status in STATUSES:
            clauses.append("status = ?")
            params.append(status)
        elif status == "active":
            clauses.append("status != 'closed'")
        if entity:
            clauses.append("entity = ?")
            params.append(entity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        min_num = _SEV_NUM.get(str(min_severity or "LOW").upper(), 1)
        want_tactic = (tactic or "").strip().lower()
        want_tech = (technique_id or "").strip().upper()
        with self._lock:
            self._prepare_read()
            try:
                rows = [dict(r) for r in self._conn.execute(
                    f"SELECT * FROM incidents {where} ORDER BY last_seen DESC LIMIT 600", params).fetchall()]
                members = self._members(
                    [r["incident_id"] for r in rows],
                    "a.alert_id, a.timestamp, a.alert_type, a.severity, a.severity_numeric, a.rule_id, "
                    "a.mitre_technique, a.message, a.tags, a.context")
            except sqlite3.Error as exc:
                logger.debug("incidents: list failed: %s", exc)
                return {"incidents": [], "total": 0, "counts": {}}
        out = []
        for row in rows:
            alerts = members.get(row["incident_id"]) or []
            for a in alerts:
                for key in ("tags", "context"):
                    try:
                        a[key] = json.loads(a.get(key) or ("[]" if key == "tags" else "{}"))
                    except (TypeError, ValueError):
                        a[key] = [] if key == "tags" else {}
            summary = summarise(row, alerts)
            if summary["severity_numeric"] < min_num:
                continue
            if want_tactic and want_tactic not in {t.lower() for t in summary["tactics"]}:
                continue
            if want_tech and want_tech not in {t["id"] for t in summary["techniques"]}:
                continue
            if rule and rule not in {r["id"] for r in summary["rules"]}:
                continue
            out.append(summary)
        out.sort(key=lambda i: (i["status"] == "closed", -i["score"], -i["last_seen"]))
        counts = {s: sum(1 for i in out if i["status"] == s) for s in STATUSES}
        return {"incidents": out[:limit], "total": len(out), "counts": counts}

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """One incident with its alerts (oldest first) and the indicators they mention."""
        with self._lock:
            self._prepare_read()
            try:
                row = self._conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
                if row is None:
                    return None
                raw = self._members([incident_id], ", ".join("a." + c.strip() for c in _ALERT_COLUMNS.split(",")),
                                    per_incident=MAX_ALERTS_PER_INCIDENT)[incident_id]
            except sqlite3.Error as exc:
                logger.debug("incidents: get failed: %s", exc)
                return None
        alerts = [parse_alert_row({k: v for k, v in a.items() if k != "incident_id"}) for a in raw]
        summary = summarise(dict(row), alerts)
        summary["alerts"] = alerts
        summary["truncated"] = int(row["alert_count"] or 0) > len(alerts) >= MAX_ALERTS_PER_INCIDENT
        summary["iocs"] = extract_iocs(alerts)
        programs: Dict[str, str] = {}
        for a in alerts:
            ctx = a.get("context") or {}
            if ctx.get("exe") and ctx["exe"] not in programs:
                programs[ctx["exe"]] = ctx.get("app") or ctx["exe"].rsplit("/", 1)[-1]
        summary["programs"] = [{"exe": exe, "app": app} for exe, app in list(programs.items())[:12]]
        return summary

    def incident_of(self, alert_id: str) -> Optional[str]:
        with self._lock:
            self._flush()
            try:
                row = self._conn.execute(
                    "SELECT incident_id FROM incident_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            except sqlite3.Error:
                return None
        return row["incident_id"] if row else None

    def update(self, incident_id: str, status: Optional[str] = None, note: Optional[str] = None) -> bool:
        """Triage: set the status (open / acknowledged / closed) and / or the analyst's note."""
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        sets, params = ["updated = ?"], [time.time()]
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if note is not None:
            sets.append("note = ?")
            params.append(str(note)[:4000])
        with self._lock:
            self._flush()
            try:
                cur = self._conn.execute(
                    f"UPDATE incidents SET {', '.join(sets)} WHERE incident_id = ?", (*params, incident_id))
                self._conn.commit()
            except sqlite3.Error as exc:
                self._rollback()
                logger.error("incidents: update failed: %s", exc)
                return False
            if cur.rowcount and status == "closed":
                # The next alert about this subject starts a new incident.
                for key in [k for k, v in self._active.items() if v[0] == incident_id]:
                    del self._active[key]
            return bool(cur.rowcount)
