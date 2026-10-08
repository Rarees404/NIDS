"""
Plain-English guidance for every alert: what happened, what it means,
how worried to be, and what to do about it.

Detector messages are terse and technical by design (they go to logs,
syslog and SQLite).  :func:`describe` turns an alert into the explanation
a non-specialist needs, using the alert's own evidence and context (which
app, which host, how often) so the text is specific to *this* event.

Every UI shows the same text: the web dashboard's alert drawer, the menu
bar app, and the macOS notification subtitle.  No network calls — this is
instant and works offline; "Explain with Claude" remains the deep dive.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from .classify import classify

# How worried to be, in words.  The UI colours these like severities.
HARMLESS = "Usually harmless"
PRIVACY = "Privacy"
CHECK = "Worth checking"
ACT = "Act now"

_PORT_NAMES = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "file sharing (SMB)", 548: "AFP file sharing",
    631: "printing", 3000: "a local web dev server", 3306: "MySQL", 3389: "Remote Desktop",
    5000: "AirPlay / dev servers", 5432: "PostgreSQL", 5900: "Screen Sharing (VNC)",
    6379: "Redis", 6463: "Discord's local RPC", 7000: "AirPlay", 8080: "a local web server",
    8888: "Jupyter", 9222: "Chrome's remote debugging", 27017: "MongoDB",
}

Guide = Dict[str, Any]


def describe(alert: Dict[str, Any]) -> Guide:
    """
    Return ``{"summary", "meaning", "verdict", "next_steps", "details"}``.

    *alert* is the dict form used by the API (``Alert.to_dict()`` or a
    stored row).  Unknown alert types fall back to a generic explanation.
    """
    kind = alert.get("kind") or classify(alert)
    rule = (alert.get("rule_id") or "").upper()
    tags = set(alert.get("tags") or ())
    ev = alert.get("evidence") or {}
    ctx = alert.get("context") or {}

    builder: Optional[Callable[..., Guide]] = _BY_RULE.get(rule)
    if builder is None:
        for tag, fn in _BY_TAG:
            if tag in tags:
                builder = fn
                break
    if builder is None:
        builder = _threat_intel if kind == "threat" else _generic
    guide = builder(alert, ev, ctx)
    guide.setdefault("details", [])
    guide["details"] = [d for d in guide["details"] + _common_details(alert, ctx) if d[1] not in (None, "")]
    return guide


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _who(ctx: Dict[str, Any], fallback: str = "A program on this Mac") -> str:
    return ctx.get("app") or fallback


def _host(alert: Dict[str, Any], ctx: Dict[str, Any], ev: Dict[str, Any]) -> str:
    return (ctx.get("remote_host") or ev.get("host") or ev.get("sni")
            or alert.get("dst_ip") or "a remote server")


def _port_name(port: Any) -> str:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "an unknown port"
    name = _PORT_NAMES.get(port)
    return f"port {port} ({name})" if name else f"port {port}"


def _interval(seconds: Any) -> str:
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "?"
    if s < 90:
        return f"every {s:.0f} seconds"
    if s < 5400:
        return f"every {s / 60:.0f} minutes"
    return f"every {s / 3600:.1f} hours"


def _common_details(alert: Dict[str, Any], ctx: Dict[str, Any]) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    if ctx.get("app"):
        proc = ctx.get("process")
        out.append(("App", ctx["app"] + (f" ({proc})" if proc and proc != ctx["app"] else "")))
    elif ctx.get("direction") in ("outbound", "local"):
        out.append(("App", "Not identified — the connection ended before it could be matched"))
    if ctx.get("system_process"):
        out.append(("Signed", "Part of macOS (runs from the protected system volume)"))
    loc = ", ".join(x for x in (ctx.get("city"), ctx.get("country_name") or ctx.get("country")) if x)
    if loc:
        out.append(("Server location", loc + (f" · {ctx['org']}" if ctx.get("org") else "")))
    conf = alert.get("confidence")
    if isinstance(conf, (int, float)):
        out.append(("Detector confidence", f"{round(conf * 100)}%"))
    return out


def _g(summary: str, meaning: str, verdict: str, steps: List[str],
       details: Optional[List[Tuple[str, Any]]] = None) -> Guide:
    return {"summary": summary, "meaning": meaning, "verdict": verdict,
            "next_steps": steps, "details": details or []}


# ---------------------------------------------------------------------------
# Builders, one per kind of alert
# ---------------------------------------------------------------------------

def _localhost_probe(alert, ev, ctx) -> Guide:
    port = alert.get("dst_port") or ev.get("destination_port")
    place = "this Mac" if ev.get("destination_class") == "loopback" else "a device on your network"
    target = ev.get("target_app") or ctx.get("target_app")
    details = [("Port", _port_name(port)), ("Listening app", target or "Nothing identified")]
    if ev.get("repeats_since_last_alert"):
        details.append(("Repeats", f"{ev['repeats_since_last_alert']} more attempts since the previous alert"))
    if ev.get("initiator") == "browser":
        return _g(
            f"{_who(ctx, 'Your browser')} tried to reach {_port_name(port)} on {place}.",
            "A web page can make your browser connect to addresses on your own computer or "
            "home network. Sites use this to detect which software you run (developer tools, "
            "remote-desktop apps, game launchers) and build a fingerprint of you. Some "
            "legitimate sites do it too, for example to talk to a companion app you installed.",
            CHECK,
            ["Look at which tab or site you had open at that moment.",
             "If it is a site you don't trust, close it; consider an extension that blocks "
             "local-network requests (uBlock Origin's 'Block Outsider Intrusion into LAN' list).",
             "If it's a site you use with a desktop companion app, this is expected."],
            details,
        )
    return _g(
        f"An unidentified program connected to {_port_name(port)} on {place}.",
        "Something opened a connection to a local service and closed it again before macOS's "
        "socket table could be sampled, so the app couldn't be named. The usual cause is a "
        "native app checking whether its own helper is running (updaters, game launchers, "
        "peripheral software do this on a timer). A website probing you is possible but would "
        "normally show your browser as the source.",
        HARMLESS,
        ["If this repeats on a fixed schedule, it's almost certainly an app's background check.",
         f"Run `sudo lsof -nP -iTCP:{port}` when it happens to see who is listening.",
         "Only worry if it coincides with visiting an unfamiliar website."],
        details,
    )


def _localhost_scan(alert, ev, ctx) -> Guide:
    ports = ev.get("ports_probed") or []
    browser = ev.get("initiator") == "browser"
    return _g(
        f"{_who(ctx, 'An unidentified program')} tried {len(ports)} different local ports in "
        f"{ev.get('window_seconds', 30):.0f} seconds.",
        "Trying many ports in quick succession is a port scan: it maps which services are "
        "running. From a browser it means a web page is fingerprinting your machine; from a "
        "native app it is unusual unless the app is a network or security tool.",
        ACT if browser else CHECK,
        (["Close the tab you had open at that time.",
          "Clear that site's data and avoid it, or block it with a content blocker."]
         if browser else
         ["Check whether the app is a network utility you installed on purpose.",
          "If you don't recognise it, quit it and look it up before running it again."]),
        [("Ports tried", ", ".join(str(p) for p in ports[:20]))],
    )


def _webrtc(alert, ev, ctx) -> Guide:
    rule = (alert.get("rule_id") or "").upper()
    if rule == "STEALTH-WEBRTC-LEAK":
        return _g(
            f"A web page learned your private IP address {ev.get('leaked_ip')} through WebRTC.",
            "WebRTC (used for video calls) asks STUN servers for every address your machine has. "
            "A page can read these even behind a VPN, revealing your internal network address. "
            "That makes you easier to track and can expose your real network when using a VPN.",
            PRIVACY,
            ["If you weren't on a video call, note which site was open.",
             "Use a browser setting or extension that limits WebRTC IP handling.",
             "On a VPN, check its WebRTC leak protection is on."],
            [("Leaked address", ev.get("leaked_ip")), ("STUN server", alert.get("src_ip"))],
        )
    if rule == "STEALTH-WEBRTC-REFLEXIVE":
        return _g(
            f"A STUN server told your browser its public address ({ev.get('leaked_ip')}).",
            "This is normal at the start of every video/voice call: the browser learns how the "
            "internet sees it so peers can connect. It also means the page can see your public IP.",
            HARMLESS,
            ["Expected during calls (Meet, Teams, Discord, WhatsApp Web).",
             "If no call was running, a site may be using WebRTC to collect your IP."],
            [("Public address", ev.get("leaked_ip"))],
        )
    return _g(
        f"{_who(ctx, 'Your browser')} started a WebRTC connection check with {alert.get('dst_ip')}.",
        "STUN/TURN requests are how calls and peer-to-peer connections find a route. Outside "
        "of a call they can be used to discover your IP addresses.",
        HARMLESS,
        ["Expected during calls and screen sharing; otherwise note which site was open."],
    )


def _quic(alert, ev, ctx) -> Guide:
    host = ev.get("sni") or alert.get("dst_ip")
    return _g(
        f"{_who(ctx, 'An app')} opened a QUIC / HTTP-3 connection to {host}.",
        "QUIC is the modern, encrypted transport behind HTTP/3, used by Google, YouTube, "
        "Cloudflare, Meta and others. It's normal; it's listed because it is invisible in a "
        "browser's network panel and older firewalls can't inspect it.",
        HARMLESS,
        ["Nothing to do; this is informational."],
        [("Server name", ev.get("sni")), ("Protocols", ", ".join(ev.get("alpn") or []) or None),
         ("Encrypted Client Hello", "yes — server name hidden" if ev.get("ech") else None)],
    )


def _tracker(alert, ev, ctx) -> Guide:
    host = ev.get("host") or _host(alert, ctx, ev)
    return _g(
        f"{_who(ctx, 'An app')} contacted {ev.get('category') or 'a tracker'} at {host}.",
        "This domain is on a public list of advertising, analytics or tracking services. "
        "Contacting it usually means a page or app is reporting your activity to a third party.",
        PRIVACY,
        ["Use a content blocker or a tracker-blocking DNS if you want to stop these.",
         "In apps, check privacy settings for 'analytics' or 'usage data' switches."],
        [("Tracker", ev.get("category")), ("Seen via", ev.get("source"))],
    )


def _doh(alert, ev, ctx) -> Guide:
    resolver = str(ev.get("resolver") or "")
    if ev.get("method") == "iCloud Private Relay" or (
            resolver.endswith(".icloud.com") and resolver.startswith("mask")):
        return _g(
            "iCloud Private Relay is active.",
            "Apple's Private Relay sends Safari traffic and DNS lookups through two relays so "
            "neither Apple nor the website sees both who you are and what you visit. Because "
            "the traffic is encrypted end-to-end, PyNIDS sees less of what Safari does.",
            HARMLESS,
            ["Nothing to do if you turned Private Relay on (System Settings → Apple ID → iCloud).",
             "For full visibility into Safari, you can pause it while investigating."],
            [("Relay host", ev.get("resolver"))],
        )
    return _g(
        f"{_who(ctx, 'An app')} used encrypted DNS ({ev.get('method')}) via {ev.get('resolver')}.",
        "Encrypted DNS hides which websites you look up from your network, which is good for "
        "privacy. It also bypasses your router's and this tool's DNS checks, so malicious "
        "domain lookups from that app can't be seen. Browsers with 'Secure DNS' turned on do this.",
        HARMLESS if ctx.get("app") else CHECK,
        ["If it's your browser's Secure DNS setting, this is expected.",
         "If you don't know which app it is, check browser settings and installed VPN/DNS apps."],
        [("Method", ev.get("method")), ("Resolver", ev.get("resolver"))],
    )


def _websocket(alert, ev, ctx) -> Guide:
    return _g(
        f"A WebSocket was opened to {ev.get('host')}.",
        "WebSockets keep a live two-way channel open (chat, live updates, collaborative apps).",
        HARMLESS,
        ["Nothing to do; informational."],
        [("Path", ev.get("path"))],
    )


def _beacon_pixel(alert, ev, ctx) -> Guide:
    return _g(
        f"A tracking beacon was sent to {ev.get('host')}.",
        "Beacons and 1×1 pixels are tiny requests pages send to report that you viewed or "
        "left a page, often after you navigate away.",
        PRIVACY,
        ["A content blocker stops most of these."],
        [("Request", f"{ev.get('method', '')} {ev.get('host', '')}{ev.get('path', '')}".strip())],
    )


def _prefetch(alert, ev, ctx) -> Guide:
    return _g(
        f"{ev.get('host_count')} different hostnames were looked up within a few seconds.",
        "Pages tell the browser to resolve and pre-connect to the servers they'll need. A burst "
        "like this is a page loading many third-party resources.",
        HARMLESS,
        ["Informational. Look at the host list to see which third parties a page pulls in."],
        [("Hosts", ", ".join((ev.get("unique_hosts") or [])[:12]))],
    )


def _beaconing(alert, ev, ctx) -> Guide:
    host = _host(alert, ctx, ev)
    bare = not ev.get("hostname_known", bool(ctx.get("remote_host")))
    return _g(
        f"{_who(ctx)} contacts {host} {_interval(ev.get('mean_interval_seconds'))}, very regularly.",
        "Software that checks in on a fixed timer is common: mail and calendar sync, update "
        "checks, chat presence. Malware that waits for commands from its operator ('command and "
        "control') does the same thing, which is why regular check-ins are flagged. "
        + ("This one talks to a bare IP address that was never looked up in DNS, which "
           "legitimate apps rarely do." if bare else
           "It talks to a named server, which is the typical pattern of a normal app."),
        CHECK if bare else HARMLESS,
        (["Find out which app this is (the App field, or `sudo lsof -nP -i @" + str(alert.get("dst_ip")) + "`).",
          "Look up the IP's owner (the Server location field or a WHOIS lookup).",
          "If you can't tie it to software you installed, block the IP from the dashboard and investigate."]
         if bare else
         ["If you recognise the app and the server name, this is normal background sync.",
          "If the app is unfamiliar, look it up before trusting it."]),
        [("Interval", _interval(ev.get("mean_interval_seconds"))),
         ("Regularity", f"CV {ev.get('coefficient_of_variation')} (0 = perfectly regular)"),
         ("Times seen", ev.get("sample_count")),
         ("Server", host)],
    )


def _brute_force(alert, ev, ctx) -> Guide:
    service = ev.get("service") or _port_name(alert.get("dst_port"))
    if ev.get("direction") == "outbound":
        return _g(
            f"{_who(ctx)} opened {ev.get('attempt_count')} {service} connections to "
            f"{_host(alert, ctx, ev)} in {ev.get('window_seconds', 30):.0f}s.",
            "Many connections from this Mac to one remote service in a short time. Developer "
            "tools do this routinely (git over SSH, deploy scripts, mail clients reconnecting). "
            "It would only matter if no tool of yours should be connecting there.",
            HARMLESS if ctx.get("app") else CHECK,
            ["If you were using git, ssh or a deploy tool, this is expected.",
             "Otherwise check which app it is before allowing it to continue."],
            [("Service", service), ("Attempts", ev.get("attempt_count"))],
        )
    return _g(
        f"{alert.get('src_ip')} made {ev.get('attempt_count')} {service} connection attempts to this machine.",
        "Repeated new connections to a login service is how password-guessing attacks look. "
        "It only matters if that service is reachable and accepts passwords.",
        ACT,
        ["If you don't need it, turn the service off (System Settings → General → Sharing).",
         "Use keys instead of passwords for SSH, and block the source IP from the dashboard."],
        [("Service", service), ("Attempts", ev.get("attempt_count")), ("Source", alert.get("src_ip"))],
    )


def _portscan(alert, ev, ctx) -> Guide:
    if "host_sweep" in (alert.get("tags") or ()):
        return _g(
            f"{alert.get('src_ip')} contacted {ev.get('unique_hosts_scanned')} different hosts on "
            f"{_port_name(ev.get('target_port'))}.",
            "Contacting many hosts on one port is a network sweep, used to discover devices.",
            CHECK,
            ["If the source is this Mac, check for network-scanning or discovery apps.",
             "If it's another device on your network, find out what it is."],
            [("Targets", ", ".join((ev.get("sample_targets") or [])[:10]))],
        )
    return _g(
        f"{alert.get('src_ip')} tried {ev.get('unique_ports_scanned')} ports on {alert.get('dst_ip')}.",
        "Trying many ports on one machine is a port scan: someone mapping which services run there.",
        CHECK,
        ["If the source is outside your network and the target is you, make sure no services "
         "are exposed that you don't need.",
         "If the source is your router or a known device, it may be a benign discovery feature."],
        [("Ports", ", ".join(str(p) for p in (ev.get("sample_ports") or [])[:20]))],
    )


def _volumetric(alert, ev, ctx) -> Guide:
    return _g(
        f"Unrequested traffic from {alert.get('src_ip')} spiked to "
        f"{ev.get('current_rate_pps', 0):.0f} packets/s.",
        "A sudden burst of traffic you didn't ask for, well above that source's normal rate. "
        "It can be a flood/DoS attempt, or a misbehaving device on your network.",
        CHECK,
        ["If it is a device on your network, restart it or check what it's doing.",
         "Repeated spikes from an internet address can be blocked from the dashboard."],
        [("Rate", f"{ev.get('current_rate_pps', 0):.0f} pkt/s (normal ≈ {ev.get('ewma_rate', 0):.0f})")],
    )


def _exfil(alert, ev, ctx) -> Guide:
    return _g(
        f"{_who(ctx)} uploaded {ev.get('megabytes')} MiB to {_host(alert, ctx, ev)} in one connection.",
        "Large uploads are normal for backups, cloud sync, sending files or video calls. "
        "Malware stealing data looks the same on the wire, so big uploads to unfamiliar "
        "destinations are worth a glance.",
        HARMLESS if ctx.get("app") and ctx.get("remote_host") else CHECK,
        ["If you were uploading or syncing something, this is expected.",
         "If you don't recognise the app or destination, investigate before it continues."],
        [("Uploaded", f"{ev.get('megabytes')} MiB"), ("Duration", f"{ev.get('duration_seconds')} s")],
    )


def _dns_tunnel(alert, ev, ctx) -> Guide:
    return _g(
        "A DNS lookup looked like data hidden inside a hostname.",
        "Very long, random-looking hostnames can carry data out through DNS, a technique "
        "malware uses to slip past firewalls. Some security and CDN products legitimately "
        "use long encoded names too.",
        CHECK,
        ["Check which app made the lookup and whether the domain belongs to a product you use."],
        [("Hostname", ev.get("query_name"))],
    )


def _web_attack(alert, ev, ctx) -> Guide:
    return _g(
        f"An HTTP request carried a web-attack pattern ({', '.join(sorted(set(alert.get('tags') or []) & {'sqli', 'xss', 'path_traversal', 'scanner'}))}).",
        "The request contained text typical of injection or vulnerability-scanning attacks. "
        "Incoming, it means someone is probing a web server on your machine; outgoing, a "
        "tool on your machine is sending attack traffic (fine if you're testing your own site).",
        ACT if (ctx.get("direction") == "inbound") else CHECK,
        ["If you run a local web server, make sure it isn't exposed to the internet.",
         "If you're doing security testing, this is expected."],
        [("Request", ev.get("uri"))],
    )


def _correlation(alert, ev, ctx) -> Guide:
    return _g(
        f"Several different detectors flagged {alert.get('src_ip')} within a short time.",
        "One alert on its own may be noise; several kinds from the same address together is "
        "a stronger signal that something coordinated is happening.",
        ACT,
        ["Review the individual alerts from this address listed in the timeline.",
         "Block the address from the dashboard if it's external and you don't recognise it."],
    )


def _threat_intel(alert, ev, ctx) -> Guide:
    indicator = ev.get("matched_indicator") or ev.get("sni") or ev.get("query_name") or alert.get("dst_ip")
    return _g(
        f"{_who(ctx)} communicated with {indicator}, which is on a threat-intelligence blocklist "
        f"({ev.get('category', 'malicious')}).",
        "Public blocklists track addresses and domains used for malware, phishing and botnets. "
        "A match is a strong signal, though lists occasionally include shared hosting or "
        "addresses that have since changed hands.",
        ACT,
        ["Block the address from the dashboard.",
         "Check which app made the connection; if it's unfamiliar, quit it and scan your Mac.",
         "If it was a website you trust, it may be a stale list entry."],
        [("Indicator", indicator), ("List category", ev.get("category"))],
    )


def _generic(alert, ev, ctx) -> Guide:
    return _g(
        alert.get("message") or "Network event detected.",
        "A detection rule matched this traffic. See the evidence below for what triggered it.",
        CHECK if alert.get("severity") in ("HIGH", "CRITICAL") else HARMLESS,
        ["Use 'Explain with Claude' for a detailed analysis of this specific event."],
    )


_BY_RULE: Dict[str, Callable[..., Guide]] = {
    "STEALTH-LOCALHOST-PROBE": _localhost_probe,
    "STEALTH-LOCALHOST-SCAN": _localhost_scan,
    "STEALTH-WEBRTC-LEAK": _webrtc,
    "STEALTH-WEBRTC-REFLEXIVE": _webrtc,
    "STEALTH-WEBRTC-STUN": _webrtc,
    "STEALTH-WEBRTC-TURN": _webrtc,
    "STEALTH-QUIC-INITIAL": _quic,
    "STEALTH-TRACKER": _tracker,
    "STEALTH-ENCRYPTED-DNS": _doh,
    "STEALTH-WEBSOCKET": _websocket,
    "STEALTH-BEACON": _beacon_pixel,
    "STEALTH-DNS-PREFETCH": _prefetch,
}

_BY_TAG: List[Tuple[str, Callable[..., Guide]]] = [
    ("beaconing", _beaconing),
    ("brute_force", _brute_force),
    ("portscan", _portscan),
    ("volumetric", _volumetric),
    ("dns_tunneling", _dns_tunnel),
    ("exfiltration", _exfil),
    ("sqli", _web_attack), ("xss", _web_attack), ("path_traversal", _web_attack), ("scanner", _web_attack),
    ("correlation", _correlation),
]
