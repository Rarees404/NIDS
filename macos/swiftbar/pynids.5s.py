#!/usr/bin/python3
# <xbar.title>PyNIDS</xbar.title>
# <xbar.version>2.0.0</xbar.version>
# <xbar.desc>Live status of the PyNIDS network monitor: threats, trackers, leaks, apps.</xbar.desc>
# <xbar.dependencies>pynids daemon (sudo pynids daemon install)</xbar.dependencies>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>true</swiftbar.hideLastUpdated>
# <swiftbar.hideDisablePlugin>true</swiftbar.hideDisablePlugin>
"""
SwiftBar / xbar plugin for PyNIDS.

Install SwiftBar (brew install --cask swiftbar), then symlink this file
into your SwiftBar plugin folder:

    ln -s "$PWD/macos/swiftbar/pynids.5s.py" ~/Library/Application\\ Support/SwiftBar/Plugins/

Standard library only — runs with the system /usr/bin/python3.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "http://127.0.0.1:8787"
TOKEN_PATHS = [
    os.path.join(os.environ.get("PYNIDS_HOME", ""), "api-token") if os.environ.get("PYNIDS_HOME") else None,
    "/Library/Application Support/PyNIDS/api-token",
    os.path.expanduser("~/Library/Application Support/PyNIDS/api-token"),
]
LEVEL = {
    "ok": ("checkmark.shield.fill", "#0ca30c,#0ca30c", "All clear"),
    "notice": ("shield.lefthalf.filled", "#b07800,#fab219", "Notable activity"),
    "warning": ("exclamationmark.shield.fill", "#ec835a,#ec835a", "High-severity activity"),
    "critical": ("xmark.shield.fill", "#d03b3b,#d03b3b", "Critical activity"),
}
SEV_ICON = {"CRITICAL": "xmark.octagon.fill", "HIGH": "exclamationmark.circle.fill",
            "MEDIUM": "exclamationmark.triangle.fill", "LOW": "info.circle"}


def token():
    for path in TOKEN_PATHS:
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def call(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("X-PyNIDS-Token", token())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read() or b"null")


def clean(text, limit=80):
    """SwiftBar treats '|' as a parameter separator — strip it from data."""
    text = str(text or "").replace("|", "¦").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} PB"


def fmt_bits(n):
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "bps" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} Tbps"


def ago(ts):
    s = max(0, time.time() - (ts or 0))
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    return f"{int(s // 3600)} h ago"


def action(argv):
    """Handle clicks: `pynids.5s.py notify on|off` / `block <ip>` / `unblock <ip>`."""
    cmd = argv[1]
    if cmd == "notify":
        call("/api/notifications", "POST", {"enabled": argv[2] == "on"})
    elif cmd == "block":
        call("/api/blocks", "POST", {"ip": argv[2], "reason": "Blocked from the menu bar", "ttl": 3600})
    elif cmd == "unblock":
        call("/api/blocks/" + argv[2], "DELETE")


def main():
    if len(sys.argv) > 2:
        try:
            action(sys.argv)
        except Exception as exc:  # noqa: BLE001
            print(f"PyNIDS: {exc}", file=sys.stderr)
        return

    me = os.path.abspath(__file__)
    try:
        s = call("/api/summary")
    except urllib.error.HTTPError as exc:
        print("| sfimage=shield.slash sfcolor=#898781")
        print("---")
        print(f"PyNIDS API error: {exc.code} | color=#d03b3b")
        print("Is the API token readable? | size=12")
        return
    except Exception:  # noqa: BLE001 — daemon down
        print("| sfimage=shield.slash sfcolor=#898781")
        print("---")
        print("PyNIDS is not running | sfimage=exclamationmark.triangle")
        print("Start it: sudo pynids daemon install | font=Menlo size=11")
        return

    st = s.get("status", {})
    level = s.get("level", "ok")
    sf, color, label = LEVEL.get(level, LEVEL["ok"])
    k = s.get("kinds", {})
    threats = k.get("threat", 0) + k.get("attack", 0)
    title = f"{threats}" if threats else ""
    if st.get("state") == "needs-root":
        sf, color, label = "shield.slash", "#898781,#898781", "Capture needs root"
    print(f"{title} | sfimage={sf} sfcolor={color}")
    print("---")
    print(f"PyNIDS — {label} | sfimage={sf} sfcolor={color}")
    ifaces = " + ".join(st.get("interfaces") or []) or "—"
    print(f"Monitoring {ifaces} · {fmt_bits(s['rates']['bps'])} · {s['rates']['pps']:.0f} pkt/s | size=12 color=#898781")
    print("---")
    rows = [
        ("Threats & attacks", threats, "exclamationmark.shield", "threat"),
        ("Trackers & beacons", k.get("tracker", 0) + k.get("beacon", 0), "eye", "tracker"),
        ("IP leaks & localhost probes", k.get("webrtc", 0) + k.get("localhost", 0), "network.badge.shield.half.filled", "webrtc"),
        ("Encrypted DNS sessions", k.get("doh", 0), "lock.shield", "doh"),
        ("QUIC / WebSocket sessions", k.get("quic", 0) + k.get("websocket", 0), "bolt.horizontal", "quic"),
    ]
    for name, n, icon, _ in rows:
        print(f"{name}: {n:,} | sfimage={icon} href={API}/#events")
    print(f"Reached {s.get('remote_count', 0):,} endpoints in {s.get('country_count', 0)} countries | sfimage=globe href={API}/#network")
    if s.get("blocked"):
        print(f"Blocked IPs: {s['blocked']} | sfimage=hand.raised href={API}/#protection")

    try:
        alerts = call("/api/alerts?limit=8&min_severity=MEDIUM")
    except Exception:  # noqa: BLE001
        alerts = []
    print("---")
    print("Recent alerts | size=12 color=#898781")
    if not alerts:
        print("Nothing notable yet | color=#898781")
    for a in alerts:
        ctx = a.get("context") or {}
        who = f"{ctx['app']}: " if ctx.get("app") else ""
        print(f"{clean(who + a['message'], 70)} | sfimage={SEV_ICON.get(a['severity'], 'info.circle')} href={API}/#events")
        print(f"--{a['severity']} · {ago(a['timestamp'])} · {clean(a.get('rule_id') or a.get('alert_type'), 40)} | size=12")
        ip = ctx.get("remote_ip") or a.get("dst_ip")
        if ip and a["severity"] in ("HIGH", "CRITICAL"):
            print(f"--Block {ip} for 1 hour | sfimage=hand.raised bash=\"{me}\" param1=block param2={ip} terminal=false refresh=true")

    if s.get("top_apps"):
        print("---")
        print("Busiest apps | size=12 color=#898781")
        for app in s["top_apps"][:5]:
            alerts_note = f" · {app['alerts']} alerts" if app.get("alerts") else ""
            print(f"{clean(app['app'], 40)} — {fmt_bytes(app['bytes'])}{alerts_note} | sfimage=app.badge href={API}/#apps")

    print("---")
    print(f"Open dashboard | sfimage=chart.bar.xaxis href={API}/ key=CmdOrCtrl+d")
    if st.get("notifications"):
        print(f"Pause notifications | sfimage=bell.slash bash=\"{me}\" param1=notify param2=off terminal=false refresh=true")
    else:
        print(f"Resume notifications | sfimage=bell bash=\"{me}\" param1=notify param2=on terminal=false refresh=true")
    print("Refresh | sfimage=arrow.clockwise refresh=true")


if __name__ == "__main__":
    main()
