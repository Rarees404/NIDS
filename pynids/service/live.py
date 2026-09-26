"""
In-memory live state behind the dashboard, menu bar app, and widget.

:class:`LiveState` plugs into the engine twice:

* as a **packet observer** — per-packet traffic accounting by app and by
  remote endpoint (bytes, packets, hostnames, countries), a per-second
  rate history, and a per-minute timeline;
* as an **alert output** — counts by kind and severity, a recent-alerts
  ring buffer, and fan-out to Server-Sent-Events subscribers.

Everything is bounded, so memory stays flat on a machine that runs for
weeks.
"""
from __future__ import annotations

import queue
import threading
import time
from collections import Counter, OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional

from ..alerts.classify import KIND_LABELS, KINDS, classify
from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, Severity

_TIMELINE_MINUTES = 60
_RATE_SECONDS = 120


class LiveState(BaseOutput):
    def __init__(self, max_recent: int = 500, max_remotes: int = 3000, max_apps: int = 500) -> None:
        self._lock = threading.RLock()
        self.started = time.time()

        self.packets = 0
        self.bytes = 0
        self.kind_counts: Counter = Counter()
        self.severity_counts: Counter = Counter()
        self.recent: Deque[Dict[str, Any]] = deque(maxlen=max_recent)

        # (unix_second, packets, bytes) — for the live throughput sparkline
        self._rate: Deque[List[float]] = deque(maxlen=_RATE_SECONDS)
        # minute bucket → {"events": n, "bytes": n, kinds…}
        self._timeline: "OrderedDict[int, Dict[str, int]]" = OrderedDict()

        self._apps: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._max_apps = max_apps
        self._remotes: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._max_remotes = max_remotes

        self._subscribers: List["queue.Queue[Dict[str, Any]]"] = []

    # ------------------------------------------------------------------
    # Packet observer
    # ------------------------------------------------------------------

    def observe_packet(self, meta: Dict[str, Any], layer7: Dict[str, Any], ctx: Dict[str, Any]) -> None:
        size = int(meta.get("packet_len") or 0)
        now = time.time()
        sec = int(now)
        with self._lock:
            self.packets += 1
            self.bytes += size
            if self._rate and self._rate[-1][0] == sec:
                self._rate[-1][1] += 1
                self._rate[-1][2] += size
            else:
                self._rate.append([sec, 1, size])
            self._bucket(now)["bytes"] += size

            direction = ctx.get("direction")
            if direction not in ("outbound", "inbound", "transit"):
                return
            remote = ctx.get("remote_ip")
            app = ctx.get("app") or "Unattributed"
            host = ctx.get("remote_host")

            a = self._apps.get(app)
            if a is None:
                a = {"app": app, "bytes_out": 0, "bytes_in": 0, "packets": 0, "alerts": 0,
                     "remotes": set(), "hosts": Counter(), "countries": Counter(),
                     "first_seen": now, "process": ctx.get("process")}
                self._apps[app] = a
                if len(self._apps) > self._max_apps:
                    self._apps.popitem(last=False)
            else:
                self._apps.move_to_end(app)
            a["packets"] += 1
            a["bytes_out" if direction == "outbound" else "bytes_in"] += size
            a["last_seen"] = now
            if remote and len(a["remotes"]) < 5000:
                a["remotes"].add(remote)
            if host:
                a["hosts"][host] += size
            if ctx.get("country"):
                a["countries"][ctx["country"]] += size

            if not remote:
                return
            r = self._remotes.get(remote)
            if r is None:
                r = {"ip": remote, "bytes": 0, "packets": 0, "apps": set(), "alerts": 0,
                     "first_seen": now}
                self._remotes[remote] = r
                if len(self._remotes) > self._max_remotes:
                    self._remotes.popitem(last=False)
            else:
                self._remotes.move_to_end(remote)
            r["bytes"] += size
            r["packets"] += 1
            r["last_seen"] = now
            if len(r["apps"]) < 20:
                r["apps"].add(app)
            for key in ("remote_host", "country", "country_name", "city", "lat", "lon", "org", "asn"):
                if ctx.get(key) is not None:
                    r[key] = ctx[key]

    def _bucket(self, now: float) -> Dict[str, int]:
        minute = int(now // 60) * 60
        bucket = self._timeline.get(minute)
        if bucket is None:
            bucket = {"events": 0, "bytes": 0, "threats": 0}
            self._timeline[minute] = bucket
            while len(self._timeline) > _TIMELINE_MINUTES:
                self._timeline.popitem(last=False)
        return bucket

    # ------------------------------------------------------------------
    # Alert output
    # ------------------------------------------------------------------

    def emit(self, alert: Alert) -> None:
        d = alert.to_dict()
        d["kind"] = classify(alert)
        with self._lock:
            self.kind_counts[d["kind"]] += 1
            self.severity_counts[alert.severity.value] += 1
            self.recent.append(d)
            bucket = self._bucket(alert.timestamp)
            bucket["events"] += 1
            if alert.severity >= Severity.HIGH or d["kind"] in ("threat", "attack"):
                bucket["threats"] += 1
            app = alert.context.get("app")
            if app and app in self._apps:
                self._apps[app]["alerts"] += 1
            remote = alert.context.get("remote_ip")
            if remote and remote in self._remotes:
                self._remotes[remote]["alerts"] += 1
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait({"type": "alert", "data": d})
            except queue.Full:
                pass

    # ------------------------------------------------------------------
    # SSE subscriptions
    # ------------------------------------------------------------------

    def subscribe(self) -> "queue.Queue[Dict[str, Any]]":
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait({"type": event_type, "data": data})
            except queue.Full:
                pass

    # ------------------------------------------------------------------
    # Snapshots for the API
    # ------------------------------------------------------------------

    def rates(self) -> Dict[str, Any]:
        now = int(time.time())
        with self._lock:
            by_sec = {int(s): (p, b) for s, p, b in self._rate}
        series = [by_sec.get(s, (0, 0)) for s in range(now - 60, now)]
        last5 = series[-5:]
        return {
            "pps": round(sum(p for p, _ in last5) / 5, 1),
            "bps": round(sum(b for _, b in last5) * 8 / 5),
            "series_pps": [p for p, _ in series],
            "series_bps": [b * 8 for _, b in series],
        }

    def timeline(self) -> List[Dict[str, Any]]:
        now_min = int(time.time() // 60) * 60
        with self._lock:
            data = dict(self._timeline)
        out = []
        for i in range(_TIMELINE_MINUTES - 1, -1, -1):
            minute = now_min - i * 60
            b = data.get(minute, {"events": 0, "bytes": 0, "threats": 0})
            out.append({"t": minute, **b})
        return out

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            kinds = {k: self.kind_counts.get(k, 0) for k in KINDS}
            sev = {s.value: self.severity_counts.get(s.value, 0) for s in Severity}
            total = sum(self.kind_counts.values())
            last_alert = self.recent[-1] if self.recent else None
            top_apps = sorted(
                self._apps.values(), key=lambda a: a["bytes_out"] + a["bytes_in"], reverse=True
            )[:5]
            top = [{"app": a["app"], "bytes": a["bytes_out"] + a["bytes_in"],
                    "alerts": a["alerts"]} for a in top_apps]
            remotes = len(self._remotes)
            countries = len({r.get("country") for r in self._remotes.values() if r.get("country")})
            packets, total_bytes = self.packets, self.bytes
        return {
            "uptime": round(time.time() - self.started),
            "packets": packets,
            "bytes": total_bytes,
            "events_total": total,
            "kinds": kinds,
            "kind_labels": KIND_LABELS,
            "severity": sev,
            "last_alert": _brief(last_alert) if last_alert else None,
            "top_apps": top,
            "remote_count": remotes,
            "country_count": countries,
            "rates": self.rates(),
        }

    def apps(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = sorted(
                self._apps.values(), key=lambda a: a["bytes_out"] + a["bytes_in"], reverse=True
            )[:limit]
            return [{
                "app": a["app"],
                "process": a.get("process"),
                "bytes_out": a["bytes_out"],
                "bytes_in": a["bytes_in"],
                "packets": a["packets"],
                "alerts": a["alerts"],
                "remotes": len(a["remotes"]),
                "top_hosts": [h for h, _ in a["hosts"].most_common(6)],
                "countries": [c for c, _ in a["countries"].most_common(6)],
                "last_seen": a.get("last_seen"),
            } for a in rows]

    def remotes(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            rows = sorted(self._remotes.values(), key=lambda r: r["bytes"], reverse=True)[:limit]
            return [{**{k: v for k, v in r.items() if k != "apps"}, "apps": sorted(r["apps"])}
                    for r in rows]

    def recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent)[-limit:][::-1]


def _brief(alert: Dict[str, Any]) -> Dict[str, Any]:
    ctx = alert.get("context") or {}
    ev = alert.get("evidence") or {}
    # The one thing the alert is *about*, for compact UIs (widget, menu bar).
    subject = (
        ctx.get("remote_host") or ev.get("host") or ev.get("resolver") or ev.get("sni")
        or ev.get("leaked_ip") or ev.get("query_name") or alert.get("dst_ip") or alert.get("src_ip")
    )
    if alert.get("kind") == "localhost" and alert.get("dst_port"):
        subject = f"{alert.get('dst_ip')}:{alert.get('dst_port')}"
    return {
        "alert_id": alert.get("alert_id"),
        "timestamp": alert.get("timestamp"),
        "severity": alert.get("severity"),
        "kind": alert.get("kind"),
        "title": KIND_LABELS.get(alert.get("kind") or "", "Alert"),
        "subject": subject,
        "message": alert.get("message"),
        "app": ctx.get("app"),
    }
