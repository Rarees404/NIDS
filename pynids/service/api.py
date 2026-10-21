"""
Local HTTP API for the dashboard, menu bar app, widget, and SwiftBar plugin.

Standard library only (``http.server``), bound to 127.0.0.1.

Security model
--------------
Anything on the machine can reach 127.0.0.1, including web pages in your
browser, which is exactly the "localhost probe" attack this tool detects.
So:

* **Host header allowlist** — requests must address ``127.0.0.1``,
  ``localhost``, or ``[::1]`` on our port.  This defeats DNS-rebinding
  attacks, where a malicious page makes its own hostname resolve to 127.0.0.1.
* **Token** — every ``/api/*`` route except ``/api/health`` and
  ``/api/widget`` needs the random token from the data directory, sent as the
  ``X-PyNIDS-Token`` header (or ``?token=`` for EventSource).
* **Origin check** — requests that change state are rejected if they carry a
  foreign ``Origin``.
* **No CORS headers** — other origins cannot read responses.

``/api/widget`` is unauthenticated so the sandboxed WidgetKit extension
(which cannot read the token file) can use it; it only returns counts and
the latest alert headline.
"""
from __future__ import annotations

import hmac
import json
import logging
import queue
import re
import sqlite3
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from ..alerts.classify import classify
from ..alerts.guide import describe
from .live import LiveState, _brief

logger = logging.getLogger(__name__)

_SEV_NUM = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ServiceContext:
    """Everything the API needs, assembled by the daemon."""

    def __init__(
        self,
        live: LiveState,
        token: str,
        db_path: Optional[Path] = None,
        status: Optional[Callable[[], Dict[str, Any]]] = None,
        blocker: Any = None,
        notifier: Any = None,
        explain: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        update_feeds: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        feed_status: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        set_detection: Optional[Callable[[bool], Dict[str, Any]]] = None,
        inspector: Any = None,
        allowlist: Any = None,
        investigate: Optional[Callable[[str], Dict[str, Any]]] = None,
        baseline: Any = None,
        updater: Any = None,
    ) -> None:
        self.live = live
        self.token = token
        self.db_path = Path(db_path) if db_path else None
        self.status = status or (lambda: {})
        self.blocker = blocker
        self.notifier = notifier
        self.explain = explain
        self.update_feeds = update_feeds
        self.feed_status = feed_status or (lambda: [])
        self.set_detection = set_detection
        self.inspector = inspector
        self.allowlist = allowlist
        self.investigate = investigate
        self.baseline = baseline
        self.updater = updater
        self._explain_lock = threading.Lock()
        self._investigate_lock = threading.Lock()
        if self.db_path:
            self._init_explanations()

    # --- persistence helpers --------------------------------------------

    def db(self) -> Optional[sqlite3.Connection]:
        if not self.db_path or not self.db_path.exists():
            return None
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_explanations(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS explanations ("
                " alert_id TEXT PRIMARY KEY, created REAL, model TEXT,"
                " verdict TEXT, text TEXT)"
            )
            conn.commit()
        finally:
            conn.close()

    def find_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for a in self.live.recent_alerts(limit=10_000):
            if a.get("alert_id") == alert_id:
                return a
        conn = self.db()
        if conn is None:
            return None
        try:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            return _row_to_alert(row) if row else None
        except sqlite3.Error:
            return None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Row helpers
# ---------------------------------------------------------------------------

def _row_to_alert(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for key in ("tags", "evidence", "context"):
        try:
            d[key] = json.loads(d.get(key) or ("[]" if key == "tags" else "{}"))
        except ValueError:
            d[key] = [] if key == "tags" else {}
    d["kind"] = classify(d)
    d["about"] = describe(d)
    return d


class _BadRequest(ValueError):
    """A malformed request parameter (answered with 400, not 500)."""


def _num(query: Dict[str, List[str]], name: str, default: Any = None, cast: Callable = int,
         lo: Optional[float] = None, hi: Optional[float] = None) -> Any:
    """Read a numeric query parameter, clamped to [lo, hi]."""
    raw = (query.get(name) or [None])[0]
    if raw in (None, ""):
        return default
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        raise _BadRequest(f"{name} must be a number") from None
    if lo is not None:
        value = max(lo, value)
    if hi is not None:
        value = min(hi, value)
    return value


def _fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 query (each word quoted, AND-ed)."""
    words = re.findall(r"[\w.:\-]+", text)
    return " ".join('"' + w.replace('"', "") + '"' for w in words[:8])


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = f"PyNIDS/{__version__}"
    ctx: ServiceContext  # set on the subclass created by make_server
    port: int

    # Silence default stderr logging; route through logging at debug.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        logger.debug("api: " + fmt, *args)

    # --- plumbing ---------------------------------------------------------

    def _allowed_host(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        allowed = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}
        return host in allowed

    def _allowed_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        return origin.lower() in {f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}",
                                  f"http://[::1]:{self.port}"}

    def _authorized(self, query: Dict[str, List[str]]) -> bool:
        supplied = self.headers.get("X-PyNIDS-Token") or (query.get("token") or [""])[0]
        return bool(self.ctx.token) and hmac.compare_digest(supplied, self.ctx.token)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status)

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 65536:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _route(self, method: str) -> None:
        if not self._allowed_host():
            self._error(HTTPStatus.FORBIDDEN, "invalid Host header")
            return
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        query = parse_qs(url.query)

        if method == "GET" and path == "/":
            self._serve_dashboard()
            return
        if method == "GET" and path == "/api/health":
            self._send_json({"ok": True, "version": __version__})
            return
        if method == "GET" and path == "/api/widget":
            self._send_json(self._widget())
            return
        if method == "GET" and path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
            return
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._authorized(query):
            self._error(HTTPStatus.UNAUTHORIZED, "missing or invalid token")
            return
        if method != "GET" and not self._allowed_origin():
            self._error(HTTPStatus.FORBIDDEN, "cross-origin request rejected")
            return

        try:
            self._dispatch(method, path, query)
        except BrokenPipeError:
            pass
        except _BadRequest as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:  # noqa: BLE001 — never kill the server thread
            logger.exception("API error on %s %s", method, path)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._route("DELETE")

    # --- routes -------------------------------------------------------------

    def _dispatch(self, method: str, path: str, query: Dict[str, List[str]]) -> None:
        ctx = self.ctx

        if method == "GET" and path == "/api/summary":
            data = ctx.live.summary()
            data["status"] = ctx.status()
            data["level"] = _threat_level(ctx.live)
            data["blocked"] = len(ctx.blocker.list()) if ctx.blocker else 0
            self._send_json(data)
        elif method == "GET" and path == "/api/alerts":
            self._send_json(self._alerts(query))
        elif method == "GET" and path == "/api/apps":
            self._send_json(ctx.live.apps(limit=_num(query, "limit", 100, lo=1, hi=1000)))
        elif method == "GET" and path == "/api/remotes":
            self._send_json(ctx.live.remotes(limit=_num(query, "limit", 500, lo=1, hi=5000)))
        elif method == "GET" and path == "/api/timeline":
            self._send_json(ctx.live.timeline())
        elif method == "GET" and path == "/api/stream":
            self._stream()
        elif method == "GET" and path == "/api/intel":
            self._send_json(ctx.feed_status())
        elif method == "POST" and path == "/api/intel/update":
            if not ctx.update_feeds:
                self._error(HTTPStatus.NOT_IMPLEMENTED, "feed updates unavailable")
                return
            self._send_json(ctx.update_feeds())
        elif path == "/api/blocks" or path.startswith("/api/blocks/"):
            self._blocks(method, path)
        elif method == "POST" and path.startswith("/api/explain/"):
            self._explain(unquote(path[len("/api/explain/"):]))
        elif method == "GET" and path.startswith("/api/alerts/"):
            alert = ctx.find_alert(unquote(path[len("/api/alerts/"):]))
            if alert:
                self._send_json(alert)
            else:
                self._error(HTTPStatus.NOT_FOUND, "alert not found")
        elif method == "POST" and path == "/api/notifications":
            if not ctx.notifier:
                self._error(HTTPStatus.NOT_IMPLEMENTED, "notifications unavailable")
                return
            ctx.notifier.enabled = bool(self._body().get("enabled", True))
            self._send_json({"enabled": ctx.notifier.enabled})
        elif method == "GET" and path == "/api/attention":
            self._send_json(self._attention())
        elif method == "GET" and path.startswith("/api/apps/"):
            name = unquote(path[len("/api/apps/"):])
            app = ctx.live.app(name)
            if not app:
                self._error(HTTPStatus.NOT_FOUND, "app not seen this session")
                return
            if ctx.baseline is not None:
                app["usual_countries"] = ctx.baseline.values(name, "country")
            self._send_json(app)
        elif path in ("/api/connections", "/api/program", "/api/launch-items", "/api/devices",
                      "/api/devices/scan") or path.startswith("/api/dossier/"):
            self._host(method, path, query)
        elif path == "/api/allowlist" or path.startswith("/api/allowlist/"):
            self._allowlist(method, path)
        elif method == "POST" and path == "/api/investigate":
            self._investigate()
        elif method == "GET" and path == "/api/baseline":
            self._send_json(ctx.baseline.status() if ctx.baseline is not None else {"enabled": False})
        elif path in ("/api/update", "/api/update/check"):
            self._update(method, path)
        elif method == "POST" and path == "/api/detection":
            if not ctx.set_detection:
                self._error(HTTPStatus.NOT_IMPLEMENTED, "pausing detection is unavailable")
                return
            self._send_json(ctx.set_detection(bool(self._body().get("enabled", True))))
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def _serve_dashboard(self) -> None:
        try:
            html = resources.files("pynids.web").joinpath("dashboard.html").read_text("utf-8")
        except (FileNotFoundError, ModuleNotFoundError):
            self._error(HTTPStatus.NOT_FOUND, "dashboard not installed")
            return
        html = html.replace("__PYNIDS_TOKEN__", self.ctx.token)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _widget(self) -> Dict[str, Any]:
        live = self.ctx.live
        s = live.summary()
        k = s["kinds"]
        # What needs attention *now*: MEDIUM+ alerts from the last hour.
        cutoff = time.time() - 3600
        notable = [a for a in live.recent_alerts(limit=500)
                   if (a.get("timestamp") or 0) >= cutoff and _SEV_NUM.get(a.get("severity"), 0) >= 2]
        # Most severe first, one row per (kind, subject) so repeats don't crowd the list.
        rows, seen = [], set()
        for a in sorted(notable, key=lambda a: (-_SEV_NUM.get(a.get("severity"), 0), -(a.get("timestamp") or 0))):
            b = _brief(a)
            key = (b["kind"], b["subject"])
            if key not in seen:
                seen.add(key)
                rows.append(b)
        host = self._host_counts()
        return {
            "flagged_programs": host.get("flagged_programs"),
            "exposed_ports": host.get("exposed_ports"),
            "paused": bool(self.ctx.status().get("paused")),
            "recent_notable": len(notable),
            "recent_high": sum(1 for a in notable if _SEV_NUM.get(a.get("severity"), 0) >= 3),
            "notable_alerts": rows[:3],
            "total_bytes": s["bytes"],
            "ok": True,
            "level": _threat_level(live),
            "events_total": s["events_total"],
            "threats": k.get("threat", 0) + k.get("attack", 0),
            "trackers": k.get("tracker", 0) + k.get("beacon", 0),
            "leaks": k.get("webrtc", 0) + k.get("localhost", 0),
            "encrypted_dns": k.get("doh", 0),
            "blocked": len(self.ctx.blocker.list()) if self.ctx.blocker else 0,
            "pps": s["rates"]["pps"],
            "bps": s["rates"]["bps"],
            "series_bps": s["rates"]["series_bps"][-30:],
            "top_apps": [a for a in s["top_apps"] if a["app"] != "Unattributed"][:4],
            "countries": s["country_count"],
            "last_alert": s["last_alert"],
            "uptime": s["uptime"],
            "status": self.ctx.status().get("state", "running"),
        }

    def _alerts(self, query: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        q1 = lambda name, default=None: (query.get(name) or [default])[0]  # noqa: E731
        limit = _num(query, "limit", 200, lo=1, hi=1000)
        kind = q1("kind")
        conn = self.ctx.db()
        if conn is None:
            rows = self.ctx.live.recent_alerts(limit=limit if not kind else 1000)
            return [r for r in rows if not kind or r.get("kind") == kind][:limit]
        clauses, params = [], []
        min_sev = (q1("min_severity") or "LOW").upper()
        if _SEV_NUM.get(min_sev, 1) > 1:
            clauses.append("severity_numeric >= ?")
            params.append(_SEV_NUM[min_sev])
        since = _num(query, "since", cast=float)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        until = _num(query, "until", cast=float)
        if until is not None:
            clauses.append("timestamp < ?")
            params.append(until)
        if q1("app"):
            clauses.append("app = ?")
            params.append(q1("app"))
        if q1("q"):
            fts = _fts_query(q1("q"))
            if fts:
                clauses.append("rowid IN (SELECT rowid FROM alerts_fts WHERE alerts_fts MATCH ?)")
                params.append(fts)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        fetch = limit if not kind else min(limit * 10, 5000)
        try:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
                (*params, fetch),
            ).fetchall()
        except sqlite3.Error as exc:
            logger.debug("alerts query failed: %s", exc)
            rows = []
        finally:
            conn.close()
        out = [_row_to_alert(r) for r in rows]
        if kind:
            out = [a for a in out if a["kind"] == kind]
        return out[:limit]

    def _stream(self) -> None:
        q = self.ctx.live.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            last_tick = 0.0
            while True:
                try:
                    event = q.get(timeout=1.0)
                    payload = json.dumps(event["data"], default=_json_default)
                    self.wfile.write(f"event: {event['type']}\ndata: {payload}\n\n".encode())
                except queue.Empty:
                    pass
                now = time.monotonic()
                if now - last_tick >= 2.0:
                    last_tick = now
                    tick = {"rates": self.ctx.live.rates(), "packets": self.ctx.live.packets}
                    self.wfile.write(f"event: tick\ndata: {json.dumps(tick)}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.ctx.live.unsubscribe(q)

    def _blocks(self, method: str, path: str) -> None:
        blocker = self.ctx.blocker
        if blocker is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, "blocking is unavailable (daemon not root?)")
            return
        from ..response.pf import BlockRefused

        if method == "GET" and path == "/api/blocks":
            self._send_json([e.__dict__ for e in blocker.list()])
        elif method == "POST" and path == "/api/blocks":
            body = self._body()
            ip = str(body.get("ip") or "").strip()
            ttl = body.get("ttl", 3600)
            try:
                entry = blocker.block(
                    ip, reason=str(body.get("reason") or "Blocked from dashboard")[:300],
                    ttl=float(ttl) if ttl else None, source="manual",
                    alert_id=body.get("alert_id"),
                )
            except BlockRefused as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            except RuntimeError as exc:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
                return
            self.ctx.live.broadcast("block", entry.__dict__)
            self._send_json(entry.__dict__, HTTPStatus.CREATED)
        elif method == "DELETE" and path.startswith("/api/blocks/"):
            ip = unquote(path[len("/api/blocks/"):])
            removed = blocker.unblock(ip)
            self.ctx.live.broadcast("unblock", {"ip": ip})
            self._send_json({"ip": ip, "removed": removed})
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    # --- static assets (vendored map libraries) -----------------------------

    _STATIC_TYPES = {".js": "application/javascript; charset=utf-8", ".json": "application/json"}

    def _serve_static(self, name: str) -> None:
        # Flat directory, fixed extensions: no path traversal possible.
        if not re.fullmatch(r"[a-z0-9][a-z0-9.\-]*\.(js|json)", name):
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        try:
            body = resources.files("pynids.web").joinpath("vendor", name).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError, IsADirectoryError, NotADirectoryError):
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", self._STATIC_TYPES[name[name.rfind("."):]])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    # --- host inspection ------------------------------------------------------

    def _host(self, method: str, path: str, query: Dict[str, List[str]]) -> None:
        insp = self.ctx.inspector
        if insp is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, "host inspection is unavailable")
            return
        q1 = lambda name, default=None: (query.get(name) or [default])[0]  # noqa: E731
        flag = lambda name: q1(name) in ("1", "true", "yes")  # noqa: E731
        if method == "GET" and path == "/api/connections":
            self._send_json(insp.connections(include_local=flag("local")))
        elif method == "GET" and path == "/api/program":
            exe = q1("exe") or ""
            if not exe.startswith("/"):
                self._error(HTTPStatus.BAD_REQUEST, "exe must be an absolute path")
                return
            self._send_json(insp.program(exe))
        elif method == "GET" and path.startswith("/api/dossier/"):
            try:
                self._send_json(insp.dossier(unquote(path[len("/api/dossier/"):]),
                                             external=flag("external"), refresh=flag("refresh")))
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
        elif method == "GET" and path == "/api/launch-items":
            self._send_json(insp.launch_items(refresh=flag("refresh")))
        elif method == "GET" and path == "/api/devices":
            from ..host.lan import nmap_path
            self._send_json({"devices": insp.lan.devices() if insp.lan else [],
                             "nmap": bool(nmap_path())})
        elif method == "POST" and path == "/api/devices/scan":
            if insp.lan is None:
                self._error(HTTPStatus.NOT_IMPLEMENTED, "LAN inventory is unavailable")
                return
            ip = str(self._body().get("ip") or "").strip()
            try:
                self._send_json(insp.lan.scan(ip))
            except PermissionError as exc:
                self._error(HTTPStatus.FORBIDDEN, str(exc))
            except RuntimeError as exc:
                self._error(HTTPStatus.BAD_GATEWAY, str(exc))
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def _allowlist(self, method: str, path: str) -> None:
        al = self.ctx.allowlist
        if al is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, "allowlist unavailable")
            return
        if method == "GET" and path == "/api/allowlist":
            self._send_json(al.rules())
        elif method == "POST" and path == "/api/allowlist":
            body = self._body()
            try:
                rule = al.add(note=str(body.get("note") or ""),
                              **{k: body.get(k) for k in ("kind", "rule_id", "app", "host", "ip")})
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self.ctx.live.broadcast("allowlist", {"added": rule})
            self._send_json(rule, HTTPStatus.CREATED)
        elif method == "DELETE" and path.startswith("/api/allowlist/"):
            removed = al.remove(unquote(path[len("/api/allowlist/"):]))
            self.ctx.live.broadcast("allowlist", {"removed": removed})
            self._send_json({"removed": removed})
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def _update(self, method: str, path: str) -> None:
        upd = self.ctx.updater
        if upd is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, "updates are unavailable")
            return
        from .updater import UpdateError

        if method == "GET" and path == "/api/update":
            self._send_json(upd.status())
        elif method == "POST" and path == "/api/update/check":
            self._send_json(upd.check())
        elif method == "POST" and path == "/api/update":
            try:
                self._send_json(upd.apply(), HTTPStatus.ACCEPTED)
            except UpdateError as exc:
                self._error(HTTPStatus.CONFLICT, str(exc))
        else:
            self._error(HTTPStatus.NOT_FOUND, "not found")

    def _investigate(self) -> None:
        ctx = self.ctx
        if ctx.investigate is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, 'Claude integration unavailable: pip install "pynids[ai]"')
            return
        question = str(self._body().get("question") or "")
        if not ctx._investigate_lock.acquire(blocking=False):
            self._error(HTTPStatus.CONFLICT, "An investigation is already running — wait for it to finish.")
            return
        from ..ai.explain import ExplainError
        try:
            self._send_json(ctx.investigate(question))
        except ExplainError as exc:
            self._error(HTTPStatus.BAD_GATEWAY, str(exc))
        finally:
            ctx._investigate_lock.release()

    def _host_counts(self) -> Dict[str, Any]:
        """Program / port counts from the (cached) socket table; nothing while paused."""
        insp = self.ctx.inspector
        if insp is None or self.ctx.status().get("paused"):
            return {}
        try:
            return insp.connections()["summary"]
        except Exception as exc:  # noqa: BLE001
            logger.debug("host counts failed: %s", exc)
            return {}

    def _attention(self) -> Dict[str, Any]:
        """The few things worth a look right now, most urgent first."""
        items: List[Dict[str, Any]] = []
        paused = bool(self.ctx.status().get("paused"))
        for row in self._widget()["notable_alerts"]:
            items.append({"level": row["severity"], "title": row.get("summary") or row["message"],
                          "detail": row["title"] + (f" · {row['app']}" if row.get("app") else ""),
                          "action": {"type": "alert", "id": row["alert_id"]}})
        insp = None if paused else self.ctx.inspector
        snap = None
        if insp is not None:
            try:
                snap = insp.connections()
            except Exception as exc:  # noqa: BLE001
                logger.debug("attention: connections failed: %s", exc)
                snap = None
            if snap:
                for prog in [p for p in snap["programs"] if p["risk"] >= 2][:4]:
                    items.append({
                        "level": "HIGH" if prog["risk"] >= 3 else "MEDIUM",
                        "title": f"{prog['app']} looks untrusted",
                        "detail": "; ".join(prog.get("reasons") or []) or ", ".join(
                            snap["flag_labels"].get(f, f) for f in prog["flags"]),
                        "action": {"type": "program", "exe": prog["exe"]},
                    })
                exposed = [r for r in snap["listening"] if "exposed" in r["flags"]
                           and r.get("signature") != "apple"]
                if exposed:
                    names = sorted({r.get("app") or r.get("process") or "?" for r in exposed})
                    items.append({
                        "level": "LOW",
                        "title": f"{len(exposed)} port{'s' if len(exposed) > 1 else ''} reachable from the network",
                        "detail": ", ".join(names[:5]) + (" …" if len(names) > 5 else ""),
                        "action": {"type": "tab", "tab": "connections"},
                    })
            if insp.lan is not None:
                new = [d for d in insp.lan.devices() if d.get("new")]
                if new:
                    items.append({"level": "LOW",
                                  "title": f"{len(new)} new device{'s' if len(new) > 1 else ''} on your network",
                                  "detail": ", ".join(d.get("name") or d.get("vendor") or d["ip"] for d in new[:4]),
                                  "action": {"type": "tab", "tab": "network"}})
        items.sort(key=lambda i: -_SEV_NUM.get(i["level"], 0))
        return {"items": items[:8], "level": _threat_level(self.ctx.live), "paused": paused,
                "host": snap["summary"] if snap else None}

    def _explain(self, alert_id: str) -> None:
        ctx = self.ctx
        conn = ctx.db()
        if conn is not None:
            try:
                row = conn.execute(
                    "SELECT * FROM explanations WHERE alert_id = ?", (alert_id,)
                ).fetchone()
            finally:
                conn.close()
            if row:
                self._send_json({**dict(row), "cached": True})
                return
        if ctx.explain is None:
            self._error(HTTPStatus.NOT_IMPLEMENTED, 'Claude integration unavailable: pip install "pynids[ai]"')
            return
        alert = ctx.find_alert(alert_id)
        if not alert:
            self._error(HTTPStatus.NOT_FOUND, "alert not found")
            return
        from ..ai.explain import ExplainError

        try:
            result = ctx.explain(alert)
        except ExplainError as exc:
            self._error(HTTPStatus.BAD_GATEWAY, str(exc))
            return
        record = {"alert_id": alert_id, "created": time.time(), "model": result["model"],
                  "verdict": result.get("verdict"), "text": result["text"]}
        if ctx.db_path:
            with ctx._explain_lock:
                conn = sqlite3.connect(str(ctx.db_path), timeout=5)
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO explanations VALUES (?, ?, ?, ?, ?)",
                        (record["alert_id"], record["created"], record["model"],
                         record["verdict"], record["text"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
        self._send_json({**record, "cached": False})


def _threat_level(live: LiveState) -> str:
    """ok / notice / warning / critical — from alerts in the last 10 minutes."""
    cutoff = time.time() - 600
    worst = 0
    for a in live.recent_alerts(limit=500):
        if (a.get("timestamp") or 0) < cutoff:
            break
        worst = max(worst, _SEV_NUM.get(a.get("severity"), 0))
    return {0: "ok", 1: "ok", 2: "notice", 3: "warning", 4: "critical"}[worst]


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


class _QuietServer(ThreadingHTTPServer):
    """Browsers drop dashboard / SSE connections all the time — not an error."""

    daemon_threads = True
    # socketserver's default listen backlog is 5; the dashboard opens more
    # parallel requests than that on load, and the overflow gets reset or
    # stalls on SYN retries ("Failed to fetch", multi-second hangs).
    request_queue_size = 128

    def handle_error(self, request: Any, client_address: Any) -> None:
        import sys as _sys
        exc = _sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def make_server(ctx: ServiceContext, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    handler = type("PyNIDSHandler", (_Handler,), {"ctx": ctx, "port": port})
    server = _QuietServer((host, port), handler)
    server.daemon_threads = True
    if port == 0:  # ephemeral (tests): record the real port for Host checks
        handler.port = server.server_address[1]
    return server
