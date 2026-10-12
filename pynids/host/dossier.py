"""
External facts about an IP address: who owns it and what it is known for.

Three free, keyless sources:

* **PTR** (reverse DNS) via the system resolver.
* **RDAP** (``rdap.org``, which redirects to the right regional registry):
  the modern, JSON version of WHOIS — network name, owner, abuse contact,
  allocation range and date.
* **Shodan InternetDB** (``internetdb.shodan.io``): open ports, tags
  (``vpn``, ``tor``, ``c2``, ``self-signed`` …) and known CVEs, from
  Shodan's passive internet-wide scans.  Nothing is scanned by us.

Privacy: every lookup tells a third party (and, for PTR, whoever runs the
IP's reverse zone, which for an attacker is the attacker) that this Mac
is curious about that address.  So lookups are **never** made for private
addresses, results are cached for a day, and the daemon's automatic
lookups are limited to IPs that raised a notable alert (configurable:
``lookups.mode`` = ``alerts`` / ``always`` / ``manual``).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import queue
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import __version__
from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, Severity

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/ip/{ip}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CACHE_TTL = 24 * 3600

Fetcher = Callable[[str, float], Optional[Dict[str, Any]]]


def is_public(ip: Optional[str]) -> bool:
    try:
        return ipaddress.ip_address((ip or "").split("%")[0]).is_global
    except ValueError:
        return False


def _http_json(url: str, timeout: float) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": f"PyNIDS/{__version__}",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https URLs
            return json.loads(resp.read(512 * 1024) or b"null")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _vcard(entity: Dict[str, Any], field: str) -> Optional[str]:
    for item in (entity.get("vcardArray") or [None, []])[1] or []:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value).strip() or None
    return None


def _walk_entities(entities: List[Dict[str, Any]], depth: int = 0):
    for e in entities or []:
        yield e
        if depth < 3:
            yield from _walk_entities(e.get("entities") or [], depth + 1)


def parse_rdap(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data:
        return {}
    out: Dict[str, Any] = {
        "network": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "range": " – ".join(x for x in (data.get("startAddress"), data.get("endAddress")) if x) or None,
        "type": data.get("type"),
    }
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        out["cidr"] = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
    for ev in data.get("events") or []:
        if ev.get("eventAction") == "registration":
            out["registered"] = (ev.get("eventDate") or "")[:10] or None
        elif ev.get("eventAction") == "last changed":
            out["updated"] = (ev.get("eventDate") or "")[:10] or None
    for e in _walk_entities(data.get("entities") or []):
        roles = e.get("roles") or []
        name = _vcard(e, "fn")
        if "registrant" in roles and name and not out.get("owner"):
            out["owner"] = name
        if "abuse" in roles and not out.get("abuse_email"):
            out["abuse_email"] = _vcard(e, "email")
    if not out.get("owner"):
        for e in _walk_entities(data.get("entities") or []):
            name = _vcard(e, "fn")
            if name and "abuse" not in (e.get("roles") or []):
                out["owner"] = name
                break
    rems = [" ".join(r.get("description") or []) for r in data.get("remarks") or []]
    if rems:
        out["remarks"] = rems[0][:300]
    return {k: v for k, v in out.items() if v}


def parse_internetdb(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data or "detail" in data:
        return {"listed": False}
    return {
        "listed": True,
        "ports": data.get("ports") or [],
        "hostnames": (data.get("hostnames") or [])[:10],
        "tags": data.get("tags") or [],
        "vulns": (data.get("vulns") or [])[:25],
        "cpes": (data.get("cpes") or [])[:10],
    }


def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    result: List[Optional[str]] = [None]

    def _work() -> None:
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            pass

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


# ---------------------------------------------------------------------------
# Lookup service with cache
# ---------------------------------------------------------------------------

class IpLookup:
    """
    Cached external lookups.

    Args:
        db_path: SQLite file for the cache (shared with the events DB).
        fetch:   Injectable ``(url, timeout) -> dict`` (tests).
        ptr:     Injectable reverse-DNS function (tests).
        mode:    ``alerts`` (default), ``always`` or ``manual`` — what the
                 daemon may look up without being asked.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        fetch: Optional[Fetcher] = None,
        ptr: Optional[Callable[[str], Optional[str]]] = None,
        mode: str = "alerts",
        timeout: float = 6.0,
        max_auto_per_hour: int = 40,
    ) -> None:
        self.db_path = Path(db_path) if db_path else None
        self.fetch = fetch or _http_json
        self.ptr = ptr or reverse_dns
        self.mode = mode if mode in ("alerts", "always", "manual") else "alerts"
        self.timeout = timeout
        self.max_auto_per_hour = max_auto_per_hour
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._queue: "queue.Queue[str]" = queue.Queue(maxsize=500)
        self._queued: set = set()
        self._auto_times: List[float] = []
        self._thread: Optional[threading.Thread] = None
        self._pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="lookup")
        if self.db_path:
            self._init_db()

    # --- cache ------------------------------------------------------------

    def _init_db(self) -> None:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.execute("CREATE TABLE IF NOT EXISTS ip_lookups (ip TEXT PRIMARY KEY, fetched REAL, data TEXT)")
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("lookup cache unavailable: %s", exc)
            self.db_path = None

    def cached(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            hit = self._mem.get(ip)
        if hit and time.time() - hit["fetched"] < CACHE_TTL:
            return hit
        if not self.db_path:
            return None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            row = conn.execute("SELECT fetched, data FROM ip_lookups WHERE ip = ?", (ip,)).fetchone()
            conn.close()
        except sqlite3.Error:
            return None
        if not row or time.time() - row[0] >= CACHE_TTL:
            return None
        data = json.loads(row[1])
        with self._lock:
            self._mem[ip] = data
        return data

    def _save(self, ip: str, data: Dict[str, Any]) -> None:
        with self._lock:
            self._mem[ip] = data
            if len(self._mem) > 5000:
                self._mem.pop(next(iter(self._mem)))
        if not self.db_path:
            return
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.execute("INSERT OR REPLACE INTO ip_lookups VALUES (?, ?, ?)",
                         (ip, data["fetched"], json.dumps(data)))
            conn.commit()
            conn.close()
        except sqlite3.Error as exc:
            logger.debug("lookup cache write failed: %s", exc)

    # --- lookups ------------------------------------------------------------

    def lookup(self, ip: str, refresh: bool = False) -> Dict[str, Any]:
        """Blocking lookup (cached).  Private addresses are never sent out."""
        if not is_public(ip):
            return {"ip": ip, "external": False, "reason": "private or reserved address — not looked up"}
        if not refresh:
            hit = self.cached(ip)
            if hit:
                return {**hit, "cached": True}
        futures = {
            "ptr": self._pool.submit(self.ptr, ip),
            "rdap": self._pool.submit(self._safe_fetch, RDAP_URL.format(ip=ip)),
            "internetdb": self._pool.submit(self._safe_fetch, INTERNETDB_URL.format(ip=ip)),
        }
        out: Dict[str, Any] = {"ip": ip, "external": True, "fetched": time.time(), "errors": {}}
        try:
            out["ptr"] = futures["ptr"].result(timeout=self.timeout)
        except Exception:  # noqa: BLE001
            out["ptr"] = None
        for key, parser in (("rdap", parse_rdap), ("internetdb", parse_internetdb)):
            try:
                raw, err = futures[key].result(timeout=self.timeout + 2)
            except Exception as exc:  # noqa: BLE001
                raw, err = None, str(exc) or "timed out"
            if err:
                out["errors"][key] = err
            out[key] = parser(raw) if raw is not None else {}
        if not out["errors"]:
            out.pop("errors")
        # Only cache answers that came back; retry failures next time.
        if "errors" not in out or len(out["errors"]) < 2:
            self._save(ip, out)
        return {**out, "cached": False}

    def _safe_fetch(self, url: str):
        try:
            return self.fetch(url, self.timeout), None
        except Exception as exc:  # noqa: BLE001 — network errors are expected
            reason = getattr(exc, "reason", None) or exc
            return None, str(reason)[:200]

    # --- background prefetch (lookups.mode) ----------------------------------

    def start(self) -> "IpLookup":
        if self.mode != "manual" and not self._thread:
            self._thread = threading.Thread(target=self._run, name="ip-lookups", daemon=True)
            self._thread.start()
        return self

    def enqueue(self, ip: str) -> bool:
        if self.mode == "manual" or not is_public(ip) or ip in self._queued or self.cached(ip):
            return False
        now = time.time()
        self._auto_times = [t for t in self._auto_times if now - t < 3600]
        if len(self._auto_times) >= self.max_auto_per_hour:
            return False
        try:
            self._queue.put_nowait(ip)
        except queue.Full:
            return False
        self._queued.add(ip)
        self._auto_times.append(now)
        return True

    def _run(self) -> None:
        while True:
            ip = self._queue.get()
            try:
                self.lookup(ip)
            except Exception as exc:  # noqa: BLE001
                logger.debug("auto lookup of %s failed: %s", ip, exc)
            finally:
                self._queued.discard(ip)


class LookupPrefetch(BaseOutput):
    """Alert output: look up the remote IP of notable alerts in the background."""

    def __init__(self, lookup: IpLookup, min_severity: Severity = Severity.MEDIUM) -> None:
        self.lookup = lookup
        self.min_severity = min_severity

    def emit(self, alert: Alert) -> None:
        if self.lookup.mode == "manual" or (alert.rule_id or "").startswith("STEALTH-"):
            return
        if self.lookup.mode == "alerts" and alert.severity < self.min_severity:
            return
        ip = alert.context.get("remote_ip") or alert.dst_ip
        if ip:
            self.lookup.enqueue(ip)
