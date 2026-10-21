"""
The investigation workbench: run sources against an indicator, with a cache,
per-source rate limits and a history of what was investigated.

The dashboard calls :meth:`Workbench.parse` once, then
:meth:`Workbench.lookup` once per source in parallel, so results appear as
each source answers instead of waiting for the slowest.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .ioc import Ioc, classify, is_public_ip, parse
from .keys import KeyStore
from .links import links
from .sources import (IPS, VERDICT_RANK, Ctx, Http, Result, Source, SourceError, all_sources,
                      urllib_http)

logger = logging.getLogger(__name__)


class LocalSource(Source):
    """What *this* Mac knows: threat-intel feeds, traffic seen, alerts raised."""

    name = "local"
    label = "PyNIDS (this Mac)"
    description = "Your threat-intel feeds, traffic this Mac exchanged with the indicator, and alerts it raised."
    types = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "sha512", "asn", "cve")
    ttl = 0  # always fresh

    def __init__(self, intel: Optional[Callable[[], Any]] = None, inspector: Any = None,
                 live: Any = None, db_path: Optional[Path] = None) -> None:
        self.intel = intel
        self.inspector = inspector
        self.live = live
        self.db_path = Path(db_path) if db_path else None

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        res = self.result(verdict="info")
        raw: Dict[str, Any] = {}
        intel = self.intel() if self.intel else None
        host = None
        if ioc.type == "url":
            from urllib.parse import urlsplit
            host = urlsplit(ioc.value).hostname
        elif ioc.type == "domain":
            host = ioc.value
        elif ioc.type == "email":
            host = ioc.value.rpartition("@")[2]

        hit = None
        if intel is not None:
            if ioc.type in IPS:
                hit = intel.check_ip(ioc.value)
            elif host:
                host_ioc = classify(host)
                if host_ioc and host_ioc.type in IPS:
                    hit = intel.check_ip(host)
                else:  # the host, then each parent domain (a.b.evil.com → b.evil.com → evil.com)
                    labels = host.split(".")
                    for i in range(len(labels) - 1):
                        hit = intel.check_domain(".".join(labels[i:]))
                        if hit:
                            break
        if hit:
            raw["intel"] = {"category": hit.category, "severity": hit.severity,
                            "description": hit.description, "indicator": hit.indicator}
            res.row("Threat-intel feed", f"{hit.category} ({hit.severity}): {hit.description} — matched {hit.indicator}")
            res.worse("malicious" if hit.severity in ("HIGH", "CRITICAL") else "suspicious")
            res.tags.append("on your blocklists")
        else:
            res.row("Threat-intel feed", "no match")

        if ioc.type in IPS and self.inspector is not None:
            try:
                local = self.inspector.dossier(ioc.value).get("local") or {}
            except Exception as exc:  # noqa: BLE001
                logger.debug("local dossier failed: %s", exc)
                local = {}
            raw["dossier"] = local
            if local.get("bytes"):
                res.row("Traffic with this Mac", f"{local['bytes']:,} bytes, {local.get('packets', 0):,} packets")
                res.row("Apps", ", ".join(local.get("apps") or []))
                res.row("Hostname seen", local.get("remote_host"))
                res.tags.append("contacted by this Mac")
            res.row("Connected right now", ", ".join(f"{c.get('app')} → {c.get('remote_port')}"
                                                     for c in local.get("connected_now") or []))
            res.pivot("domain", local.get("remote_host"), "seen in traffic")
        elif host and self.live is not None:
            seen = [(ip, r) for ip, r in self.live.remote_index().items()
                    if (r.get("remote_host") or "").lower().rstrip(".") in (host, )
                    or (r.get("remote_host") or "").lower().endswith("." + host)]
            raw["remotes"] = {ip: r for ip, r in seen}
            if seen:
                res.row("Contacted by this Mac", f"{len(seen)} address(es), "
                        f"{sum(r.get('bytes') or 0 for _, r in seen):,} bytes")
                res.tags.append("contacted by this Mac")
            for ip, r in seen[:30]:
                res.pivot("ipv6" if ":" in ip else "ipv4", ip, r.get("remote_host") or "")

        alerts = self._alerts(ioc.value if ioc.type != "url" else (host or ioc.value))
        raw["alerts"] = alerts
        res.row("Alerts mentioning it", len(alerts))
        if alerts:
            res.row("Latest alerts", [f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(a['timestamp']))} · "
                                      f"{a['severity']} · {a['message'][:140]}" for a in alerts[:10]])
            if any(a["severity"] in ("HIGH", "CRITICAL") for a in alerts):
                res.worse("suspicious")
        res.raw = raw
        return res

    def _alerts(self, term: str, limit: int = 25) -> List[Dict[str, Any]]:
        if not self.db_path or not self.db_path.exists():
            return []
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT alert_id, timestamp, severity, rule_id, message FROM alerts WHERE rowid IN "
                    "(SELECT rowid FROM alerts_fts WHERE alerts_fts MATCH ?) ORDER BY timestamp DESC LIMIT ?",
                    ('"' + term.replace('"', "") + '"', limit)).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT alert_id, timestamp, severity, rule_id, message FROM alerts WHERE src_ip = ? "
                    "OR dst_ip = ? OR message LIKE ? ORDER BY timestamp DESC LIMIT ?",
                    (term, term, f"%{term}%", limit)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []


class _RateLimiter:
    def __init__(self) -> None:
        self._calls: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def acquire(self, name: str, per_minute: Optional[int]) -> Optional[float]:
        """None if allowed now, else seconds until the next slot."""
        if not per_minute:
            return None
        now = time.time()
        with self._lock:
            calls = [t for t in self._calls.get(name, []) if now - t < 60]
            if len(calls) >= per_minute:
                self._calls[name] = calls
                return 60 - (now - calls[0])
            calls.append(now)
            self._calls[name] = calls
            return None


class Workbench:
    def __init__(self, db_path: Optional[Path] = None, keys: Optional[KeyStore] = None,
                 local: Optional[LocalSource] = None, http: Optional[Http] = None,
                 sources: Optional[List[Source]] = None) -> None:
        self.db_path = Path(db_path) if db_path else None
        self.keys = keys or KeyStore(None)
        self.http = http or urllib_http
        self.sources = {s.name: s for s in (sources if sources is not None else all_sources(local))}
        self.limiter = _RateLimiter()
        if self.db_path:
            self._init_db()

    # --- storage --------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = self._conn()
            conn.executescript(
                "CREATE TABLE IF NOT EXISTS soc_lookups (source TEXT, kind TEXT, value TEXT, fetched REAL,"
                " data TEXT, PRIMARY KEY (source, kind, value));"
                "CREATE TABLE IF NOT EXISTS soc_history (kind TEXT, value TEXT, last REAL, count INTEGER,"
                " verdict TEXT, PRIMARY KEY (kind, value));")
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            logger.warning("workbench cache unavailable: %s", exc)
            self.db_path = None

    def _cached(self, src: Source, ioc: Ioc) -> Optional[Dict[str, Any]]:
        if not self.db_path or not src.ttl:
            return None
        try:
            conn = self._conn()
            row = conn.execute("SELECT fetched, data FROM soc_lookups WHERE source=? AND kind=? AND value=?",
                               (src.name, ioc.type, ioc.value)).fetchone()
            conn.close()
        except sqlite3.Error:
            return None
        if not row or time.time() - row["fetched"] > src.ttl:
            return None
        return {**json.loads(row["data"]), "cached": True}

    def _store(self, src: Source, ioc: Ioc, data: Dict[str, Any]) -> None:
        if not self.db_path or not src.ttl or data["status"] not in ("ok", "not_found"):
            return
        try:
            conn = self._conn()
            conn.execute("INSERT OR REPLACE INTO soc_lookups VALUES (?, ?, ?, ?, ?)",
                         (src.name, ioc.type, ioc.value, data["fetched"], json.dumps(data, default=str)))
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("workbench cache write failed: %s", exc)

    def _remember(self, ioc: Ioc, verdict: Optional[str] = None) -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            row = conn.execute("SELECT verdict FROM soc_history WHERE kind=? AND value=?",
                               (ioc.type, ioc.value)).fetchone()
            if row is None:
                conn.execute("INSERT INTO soc_history VALUES (?, ?, ?, 1, ?)",
                             (ioc.type, ioc.value, time.time(), verdict or "unknown"))
            elif verdict is None:
                conn.execute("UPDATE soc_history SET last=?, count=count+1 WHERE kind=? AND value=?",
                             (time.time(), ioc.type, ioc.value))
            elif VERDICT_RANK.get(verdict, 0) > VERDICT_RANK.get(row["verdict"], 0):
                conn.execute("UPDATE soc_history SET verdict=? WHERE kind=? AND value=?",
                             (verdict, ioc.type, ioc.value))
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("workbench history write failed: %s", exc)

    # --- public API -----------------------------------------------------

    def describe_sources(self) -> List[Dict[str, Any]]:
        return [s.describe(self.keys.configured(s.key) if s.key else True) for s in self.sources.values()]

    def parse(self, text: str) -> Dict[str, Any]:
        """Recognise the input; for each indicator, list the sources and links that apply."""
        iocs = parse(text or "")
        out = []
        for ioc in iocs:
            usable = [s for s in self.sources.values() if s.supports(ioc)]
            out.append({
                **ioc.to_dict(),
                "public": is_public_ip(ioc.value) if ioc.type in IPS else None,
                "sources": [s.name for s in usable],
                "links": links(ioc),
            })
        if len(iocs) == 1:
            self._remember(iocs[0])
        return {"input": text, "iocs": out, "single": len(iocs) == 1}

    def lookup(self, source: str, kind: str, value: str, refresh: bool = False) -> Dict[str, Any]:
        src = self.sources.get(source)
        if src is None:
            raise KeyError(f"unknown source: {source}")
        ioc = classify(value)
        if ioc is None or ioc.type != kind:
            ioc = Ioc(kind, value, value) if ioc is None else ioc
        if not src.supports(ioc):
            return Result(source=source, status="unsupported", message=f"{src.label} doesn't handle {ioc.type}").to_dict()
        key = self.keys.get(src.key) if src.key else None
        if src.key and not key and not src.key_optional:
            return Result(source=source, status="needs_key", message=src.key_help).to_dict()
        if not refresh:
            hit = self._cached(src, ioc)
            if hit:
                return hit
        wait = self.limiter.acquire(src.name, src.per_minute)
        if wait is not None:
            res = Result(source=source, status="rate_limited",
                         message=f"free-tier limit of {src.per_minute}/min — retrying in {round(wait)} s")
            return {**res.to_dict(), "retry_after": max(1, round(wait))}
        try:
            res = src.query(ioc, Ctx(http=self.http, key=key))
        except SourceError as exc:
            res = Result(source=source, status="error", message=str(exc))
        except (OSError, ValueError) as exc:
            reason = getattr(exc, "reason", None) or exc
            res = Result(source=source, status="error", message=f"{type(exc).__name__}: {reason}"[:300])
        except Exception as exc:  # noqa: BLE001 — a broken source must not break the page
            logger.exception("source %s failed on %s", source, ioc.value)
            res = Result(source=source, status="error", message=f"internal error: {exc}"[:300])
        data = res.to_dict()
        self._store(src, ioc, data)
        if res.status == "ok":
            self._remember(ioc, res.verdict)
        return data

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        if not self.db_path:
            return []
        try:
            conn = self._conn()
            rows = conn.execute("SELECT * FROM soc_history ORDER BY last DESC LIMIT ?", (limit,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def clear_history(self) -> None:
        if not self.db_path:
            return
        conn = self._conn()
        conn.execute("DELETE FROM soc_history")
        conn.commit()
        conn.close()
