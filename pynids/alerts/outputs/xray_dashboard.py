"""
X-Ray Live Dashboard — render hidden browser/website activity in the terminal.

This output backend is the visual centrepiece of ``pynids xray``.  It
subscribes to the alert manager and maintains a small, in-memory model
of every category of stealth event the detectors emit; a background
``rich.live.Live`` thread re-renders the layout a few times per second
so the dashboard feels live and responsive.

Layout
------
::

    ┌─ banner — name, interface, packets/s, hidden events count ──┐
    ├──────────────────────────────────┬──────────────────────────┤
    │ WebRTC / IP Leaks                │ Localhost & Private      │
    │   peers + leaked IPs             │ Probes                   │
    ├──────────────────────────────────┼──────────────────────────┤
    │ QUIC / HTTP-3 endpoints          │ WebSocket sessions       │
    ├──────────────────────────────────┴──────────────────────────┤
    │ Trackers / Beacons / DNS prefetch                           │
    ├─────────────────────────────────────────────────────────────┤
    │ Live event stream — newest at the bottom                    │
    └─────────────────────────────────────────────────────────────┘

The backend is thread-safe: ``emit`` runs on the engine thread and only
mutates protected state under a lock, while the rendering thread reads
the state under the same lock.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, Optional, Tuple

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..manager import BaseOutput
from ..model import Alert, Severity


# ---------------------------------------------------------------------------
# Visual constants
# ---------------------------------------------------------------------------

_SEV_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
}

_KIND_STYLES = {
    "webrtc": "bold magenta",
    "localhost": "bold red",
    "quic": "bright_cyan",
    "websocket": "bright_blue",
    "tracker": "bright_yellow",
    "beacon": "yellow",
    "prefetch": "dim cyan",
    "other": "white",
}


# ---------------------------------------------------------------------------
# X-Ray output backend
# ---------------------------------------------------------------------------

class XRayDashboard(BaseOutput):
    """
    Rich-Live multi-panel dashboard for stealth/X-Ray events.

    Args:
        iface:         Interface name shown in the banner (purely cosmetic).
        refresh_hz:    Render rate.  4-6 Hz feels live without flickering.
        max_stream:    Lines kept in the bottom event-stream panel.
        max_per_panel: Rows kept in each summary panel.
        console:       Optional :class:`rich.console.Console` (testing).
    """

    def __init__(
        self,
        iface: str = "?",
        refresh_hz: float = 6.0,
        max_stream: int = 200,
        max_per_panel: int = 12,
        console: Optional[Console] = None,
    ) -> None:
        self._iface = iface
        self._refresh_hz = refresh_hz
        self._max_stream = max_stream
        self._max_per_panel = max_per_panel
        self._console = console or Console(highlight=False)
        self._lock = threading.RLock()

        # Aggregate counters.
        self._counts: Dict[str, int] = {
            "webrtc": 0,
            "localhost": 0,
            "quic": 0,
            "websocket": 0,
            "tracker": 0,
            "beacon": 0,
            "prefetch": 0,
            "other": 0,
            "total": 0,
        }
        self._severity_counts: Dict[Severity, int] = {s: 0 for s in Severity}

        # Per-panel rolling state.
        self._webrtc: Deque[Dict[str, Any]] = deque(maxlen=max_per_panel)
        self._webrtc_keys: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]] = {}

        self._localhost: Deque[Dict[str, Any]] = deque(maxlen=max_per_panel)
        self._localhost_keys: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

        self._quic: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._websocket: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._trackers: Dict[Tuple[str, str], Dict[str, Any]] = {}

        self._stream: Deque[Dict[str, Any]] = deque(maxlen=max_stream)
        self._start_time = time.time()

        # Live rendering thread.
        self._stop_event = threading.Event()
        self._live: Optional[Live] = None
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin rendering the dashboard.  Idempotent."""
        if self._live is not None:
            return
        self._live = Live(
            self._render(),
            console=self._console,
            screen=True,
            redirect_stdout=False,
            refresh_per_second=self._refresh_hz,
        )
        self._live.start()
        self._thread = threading.Thread(target=self._render_loop, name="xray-render", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._live:
            try:
                self._live.update(self._render())
            except Exception:
                pass
            self._live.stop()
            self._live = None

    # ------------------------------------------------------------------
    # Alert ingest
    # ------------------------------------------------------------------

    def emit(self, alert: Alert) -> None:
        kind = self._classify(alert)
        with self._lock:
            self._counts["total"] += 1
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._severity_counts[alert.severity] = (
                self._severity_counts.get(alert.severity, 0) + 1
            )
            self._stream.append(
                {
                    "timestamp": alert.timestamp,
                    "kind": kind,
                    "severity": alert.severity,
                    "message": alert.message,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "dst_port": alert.dst_port,
                }
            )

            ev = alert.evidence or {}
            if kind == "webrtc":
                self._ingest_webrtc(alert, ev)
            elif kind == "localhost":
                self._ingest_localhost(alert, ev)
            elif kind == "quic":
                self._ingest_quic(alert, ev)
            elif kind == "websocket":
                self._ingest_websocket(alert, ev)
            elif kind == "tracker":
                self._ingest_tracker(alert, ev)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(alert: Alert) -> str:
        rid = (alert.rule_id or "").upper()
        tags = set(alert.tags or [])
        if "webrtc" in tags or "STEALTH-WEBRTC" in rid or rid.startswith("STEALTH-WEBRTC"):
            return "webrtc"
        if "localhost_probe" in tags or "localhost_scan" in tags or "STEALTH-LOCALHOST" in rid:
            return "localhost"
        if "quic" in tags or "STEALTH-QUIC" in rid:
            return "quic"
        if "websocket" in tags or "STEALTH-WEBSOCKET" in rid:
            return "websocket"
        if "tracker" in tags or "STEALTH-TRACKER" in rid:
            return "tracker"
        if "beacon" in tags or "STEALTH-BEACON" in rid:
            return "beacon"
        if "dns_prefetch" in tags or "STEALTH-DNS-PREFETCH" in rid:
            return "prefetch"
        return "other"

    # ------------------------------------------------------------------
    # Per-panel ingest helpers
    # ------------------------------------------------------------------

    def _ingest_webrtc(self, alert: Alert, ev: Dict[str, Any]) -> None:
        leaked_ip = ev.get("leaked_ip")
        leaked_class = ev.get("leaked_address_class") or "-"
        key = (alert.src_ip or "?", alert.dst_ip or "?", leaked_ip)
        item = self._webrtc_keys.get(key)
        if item is None:
            item = {
                "src": alert.src_ip,
                "dst": alert.dst_ip,
                "dst_port": alert.dst_port,
                "leaked_ip": leaked_ip,
                "leaked_class": leaked_class,
                "msg_type": ev.get("message_type"),
                "is_turn": ev.get("is_turn", False),
                "severity": alert.severity,
                "count": 0,
            }
            self._webrtc_keys[key] = item
            self._webrtc.append(item)
        item["count"] += 1
        item["last_seen"] = alert.timestamp
        if alert.severity > item["severity"]:
            item["severity"] = alert.severity
        # Always keep the most-private leak we've observed.
        if leaked_ip and leaked_class in ("loopback", "private", "link_local"):
            item["leaked_ip"] = leaked_ip
            item["leaked_class"] = leaked_class

    def _ingest_localhost(self, alert: Alert, ev: Dict[str, Any]) -> None:
        port = alert.dst_port or 0
        key = (alert.src_ip or "?", alert.dst_ip or "?", port)
        item = self._localhost_keys.get(key)
        if item is None:
            item = {
                "src": alert.src_ip,
                "dst": alert.dst_ip,
                "port": port,
                "transport": ev.get("transport") or alert.protocol,
                "kind": ev.get("destination_class") or "private",
                "severity": alert.severity,
                "count": 0,
            }
            self._localhost_keys[key] = item
            self._localhost.append(item)
        item["count"] += 1
        item["last_seen"] = alert.timestamp
        if alert.severity > item["severity"]:
            item["severity"] = alert.severity
        if "ports_probed" in ev:
            item["ports_probed"] = ev["ports_probed"]

    def _ingest_quic(self, alert: Alert, ev: Dict[str, Any]) -> None:
        key = (alert.src_ip or "?", alert.dst_ip or "?")
        item = self._quic.get(key) or {
            "src": alert.src_ip,
            "dst": alert.dst_ip,
            "port": alert.dst_port,
            "version": ev.get("version"),
            "count": 0,
        }
        item["count"] += 1
        item["last_seen"] = alert.timestamp
        self._quic[key] = item

    def _ingest_websocket(self, alert: Alert, ev: Dict[str, Any]) -> None:
        host = ev.get("host") or alert.dst_ip or "?"
        key = (alert.src_ip or "?", host)
        item = self._websocket.get(key) or {
            "src": alert.src_ip,
            "host": host,
            "path": ev.get("path"),
            "count": 0,
        }
        item["count"] += 1
        item["last_seen"] = alert.timestamp
        self._websocket[key] = item

    def _ingest_tracker(self, alert: Alert, ev: Dict[str, Any]) -> None:
        host = ev.get("host") or alert.dst_ip or "?"
        category = ev.get("category") or "tracker"
        key = (alert.src_ip or "?", host)
        item = self._trackers.get(key) or {
            "src": alert.src_ip,
            "host": host,
            "category": category,
            "source": ev.get("source"),
            "count": 0,
        }
        item["count"] += 1
        item["last_seen"] = alert.timestamp
        self._trackers[key] = item

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_loop(self) -> None:
        period = 1.0 / max(self._refresh_hz, 0.5)
        while not self._stop_event.wait(timeout=period):
            try:
                if self._live is not None:
                    self._live.update(self._render())
            except Exception:
                pass

    def _render(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="banner", size=4),
            Layout(name="top", size=self._max_per_panel + 4),
            Layout(name="middle", size=self._max_per_panel + 4),
            Layout(name="trackers", size=12),
            Layout(name="stream", ratio=1, minimum_size=10),
        )
        layout["top"].split_row(
            Layout(self._panel_webrtc(), name="webrtc"),
            Layout(self._panel_localhost(), name="localhost"),
        )
        layout["middle"].split_row(
            Layout(self._panel_quic(), name="quic"),
            Layout(self._panel_websocket(), name="websocket"),
        )
        layout["banner"].update(self._banner())
        layout["trackers"].update(self._panel_trackers_beacons())
        layout["stream"].update(self._panel_stream())
        return layout

    # --- Banner ---------------------------------------------------------

    def _banner(self) -> Panel:
        with self._lock:
            uptime = time.time() - self._start_time
            counts = dict(self._counts)
            sev = dict(self._severity_counts)

        h, m = divmod(int(uptime), 3600)
        m, s = divmod(m, 60)
        uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

        title = Text("PyNIDS X-Ray", style="bold cyan")
        subtitle = Text(
            "  what your browser hides from DevTools",
            style="dim italic",
        )

        meter = Text()
        meter.append(f"iface ", style="dim")
        meter.append(self._iface, style="bold")
        meter.append(f"   uptime ", style="dim")
        meter.append(uptime_str, style="bold")
        meter.append(f"   hidden events ", style="dim")
        meter.append(str(counts.get("total", 0)), style="bold yellow")
        meter.append(f"   leaks ", style="dim")
        meter.append(
            str(counts.get("webrtc", 0) + counts.get("localhost", 0)),
            style="bold red",
        )
        meter.append(f"   trackers ", style="dim")
        meter.append(str(counts.get("tracker", 0)), style="bold yellow")
        meter.append(f"   beacons ", style="dim")
        meter.append(str(counts.get("beacon", 0)), style="yellow")
        meter.append(f"   crit/high ", style="dim")
        meter.append(
            f"{sev.get(Severity.CRITICAL, 0)}/{sev.get(Severity.HIGH, 0)}",
            style="bold red",
        )

        body = Group(Text.assemble(title, subtitle), meter)
        return Panel(body, border_style="cyan", padding=(0, 1))

    # --- Panel: WebRTC --------------------------------------------------

    def _panel_webrtc(self) -> Panel:
        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("when", style="dim", width=8)
        table.add_column("local → STUN", overflow="fold")
        table.add_column("leaked IP", overflow="fold")
        table.add_column("kind")
        table.add_column("×", justify="right", width=4)

        with self._lock:
            items = [it for it in self._webrtc][-self._max_per_panel:]

        if not items:
            return self._empty_panel(
                "WebRTC / IP leaks",
                "No STUN/TURN traffic seen yet.",
                border="magenta",
            )

        for it in reversed(items):
            ts = self._fmt_time(it.get("last_seen"))
            src = f"{it.get('src')}"
            dst = f"{it.get('dst')}:{it.get('dst_port') or '?'}"
            leaked_ip = it.get("leaked_ip") or "—"
            cls = it.get("leaked_class") or "—"
            cls_style = {
                "loopback": "bold red",
                "private": "bold yellow",
                "link_local": "yellow",
                "public": "cyan",
            }.get(cls, "white")
            sev_style = _SEV_STYLE.get(it.get("severity", Severity.LOW), "white")
            table.add_row(
                ts,
                Text(f"{src} → {dst}", style=sev_style),
                Text(leaked_ip, style=cls_style),
                Text(cls, style=cls_style),
                str(it.get("count", 1)),
            )

        return Panel(
            table,
            title="[bold magenta]WebRTC / IP leaks[/]",
            subtitle=f"[dim]{len(items)} peer{'' if len(items) == 1 else 's'}[/]",
            border_style="magenta",
        )

    # --- Panel: Localhost / Private probes -----------------------------

    def _panel_localhost(self) -> Panel:
        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("when", style="dim", width=8)
        table.add_column("source", overflow="fold")
        table.add_column("→ target", overflow="fold")
        table.add_column("kind")
        table.add_column("×", justify="right", width=4)

        with self._lock:
            items = [it for it in self._localhost][-self._max_per_panel:]

        if not items:
            return self._empty_panel(
                "Localhost / private probes",
                "No suspicious internal-LAN connections seen.",
                border="red",
            )

        for it in reversed(items):
            ts = self._fmt_time(it.get("last_seen"))
            src = it.get("src") or "?"
            dst = f"{it.get('dst')}:{it.get('port') or '?'} ({it.get('transport') or '?'})"
            kind = it.get("kind") or "?"
            kind_style = {
                "loopback": "bold red",
                "private": "yellow",
                "link_local": "cyan",
            }.get(kind, "white")
            sev_style = _SEV_STYLE.get(it.get("severity", Severity.MEDIUM), "white")
            table.add_row(
                ts,
                src,
                Text(dst, style=sev_style),
                Text(kind, style=kind_style),
                str(it.get("count", 1)),
            )

        return Panel(
            table,
            title="[bold red]Localhost / private probes[/]",
            subtitle="[dim]browser-side fingerprinting candidates[/]",
            border_style="red",
        )

    # --- Panel: QUIC / HTTP-3 ------------------------------------------

    def _panel_quic(self) -> Panel:
        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("when", style="dim", width=8)
        table.add_column("local → endpoint", overflow="fold")
        table.add_column("version")
        table.add_column("×", justify="right", width=4)

        with self._lock:
            items = sorted(
                self._quic.values(), key=lambda x: x.get("last_seen", 0), reverse=True
            )[: self._max_per_panel]

        if not items:
            return self._empty_panel(
                "QUIC / HTTP-3",
                "No QUIC initial packets seen.",
                border="bright_cyan",
            )

        for it in items:
            ts = self._fmt_time(it.get("last_seen"))
            target = f"{it.get('dst')}:{it.get('port') or '?'}"
            table.add_row(
                ts,
                f"{it.get('src')} → {target}",
                Text(it.get("version") or "?", style="bright_cyan"),
                str(it.get("count", 1)),
            )

        return Panel(
            table,
            title="[bold bright_cyan]QUIC / HTTP-3 endpoints[/]",
            subtitle="[dim]invisible in DevTools 'Network'[/]",
            border_style="bright_cyan",
        )

    # --- Panel: WebSockets ---------------------------------------------

    def _panel_websocket(self) -> Panel:
        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("when", style="dim", width=8)
        table.add_column("host", overflow="fold")
        table.add_column("path", overflow="fold")
        table.add_column("×", justify="right", width=4)

        with self._lock:
            items = sorted(
                self._websocket.values(), key=lambda x: x.get("last_seen", 0), reverse=True
            )[: self._max_per_panel]

        if not items:
            return self._empty_panel(
                "WebSocket sessions",
                "No WebSocket upgrades observed.",
                border="bright_blue",
            )

        for it in items:
            ts = self._fmt_time(it.get("last_seen"))
            table.add_row(
                ts,
                Text(it.get("host") or "?", style="bright_blue"),
                Text((it.get("path") or "/")[:40], style="dim"),
                str(it.get("count", 1)),
            )

        return Panel(
            table,
            title="[bold bright_blue]WebSocket sessions[/]",
            subtitle="[dim]long-lived bi-directional channels[/]",
            border_style="bright_blue",
        )

    # --- Panel: Trackers + Beacons -------------------------------------

    def _panel_trackers_beacons(self) -> Panel:
        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("category", style="bright_yellow", overflow="fold")
        table.add_column("host", overflow="fold")
        table.add_column("source", overflow="fold")
        table.add_column("×", justify="right", width=4)

        with self._lock:
            items = sorted(
                self._trackers.values(), key=lambda x: x["count"], reverse=True
            )[:8]
            beacons = self._counts.get("beacon", 0)
            prefetch = self._counts.get("prefetch", 0)

        if not items:
            content = Text(
                "No third-party trackers detected yet — keep browsing…",
                style="dim italic",
            )
        else:
            for it in items:
                table.add_row(
                    it.get("category") or "?",
                    it.get("host") or "?",
                    it.get("source") or "?",
                    str(it.get("count", 1)),
                )
            content = table

        footer = Text()
        footer.append(f"   beacons/pixels: ", style="dim")
        footer.append(str(beacons), style="bold yellow")
        footer.append(f"   dns prefetch storms: ", style="dim")
        footer.append(str(prefetch), style="bold cyan")

        return Panel(
            Group(content, footer),
            title="[bold bright_yellow]Trackers · Beacons · Prefetch[/]",
            border_style="bright_yellow",
        )

    # --- Panel: Live event stream --------------------------------------

    def _panel_stream(self) -> Panel:
        with self._lock:
            events = list(self._stream)

        if not events:
            return self._empty_panel(
                "Live event stream",
                "Waiting for the first hidden event…  (try opening any major website)",
                border="white",
            )

        table = Table(show_edge=False, expand=True, pad_edge=False, box=None)
        table.add_column("time", style="dim", width=12)
        table.add_column("kind", width=10)
        table.add_column("severity", width=10)
        table.add_column("flow", overflow="fold")
        table.add_column("description", overflow="fold")

        # Show the most recent ~ rows that fit; reverse so newest is at top.
        for ev in events[-25:]:
            ts = datetime.fromtimestamp(ev["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
            kind = ev["kind"]
            kind_text = Text(kind.upper().center(8), style=_KIND_STYLES.get(kind, "white"))
            sev = ev["severity"]
            sev_text = Text(f" {sev.value:<8}", style=_SEV_STYLE.get(sev, "white"))
            src = ev.get("src_ip") or "?"
            dst = ev.get("dst_ip") or "-"
            port = ev.get("dst_port")
            flow = f"{src} → {dst}" + (f":{port}" if port else "")
            table.add_row(ts, kind_text, sev_text, flow, ev["message"][:200])

        return Panel(
            table,
            title="[bold]Live event stream[/] [dim](newest at the bottom)[/]",
            border_style="white",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_panel(title: str, msg: str, border: str = "white") -> Panel:
        return Panel(
            Align.center(Text(msg, style="dim italic"), vertical="middle"),
            title=f"[bold]{title}[/]",
            border_style=border,
        )

    @staticmethod
    def _fmt_time(ts: Optional[float]) -> str:
        if not ts:
            return "--:--:--"
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
