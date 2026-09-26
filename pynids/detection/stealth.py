"""
Stealth-activity detectors — the X-Ray of browser/website behaviour.

The DevTools Network tab is a curated view: it shows the renderer's own
``fetch``/``XHR`` calls and very little else.  This module surfaces the
*hidden* activity that webpages routinely perform without showing up in
that view, so the user finally sees what their browser is doing on
their behalf.

Detectors in this file
----------------------
:class:`WebRtcLeakDetector`
    STUN/TURN traffic seen on any UDP port.  When the STUN reply
    contains an ``XOR-MAPPED-ADDRESS`` we extract the leaked IP — this
    is the long-known privacy hole that lets a website learn the user's
    public **and** private IPs even behind a NAT/VPN.

:class:`LocalhostProbeDetector`
    TCP SYNs (and UDP datagrams) directed at 127.0.0.0/8 or RFC1918
    space on uncommon ports — a classic browser-side fingerprinting
    technique used to detect locally-running developer tools, password
    managers, malware-analysis sandboxes, etc.

:class:`QuicHttp3Detector`
    QUIC Initial packets — every HTTP/3 connection starts here and is
    invisible in DevTools (only the resulting fetches are logged).

:class:`WebSocketDetector`
    HTTP ``Upgrade: websocket`` handshakes — the underlying transport
    behind Chrome's "WS" sub-tab.

:class:`BeaconDetector`
    ``navigator.sendBeacon`` POSTs and 1×1 tracking-pixel GETs that
    routinely escape the user's attention.

:class:`DnsPrefetchDetector`
    Bursts of unique third-party DNS lookups from the same source
    within a few seconds — the signature of ``<link rel="dns-prefetch">``
    and ``<link rel="preconnect">`` hints fired before any user action.

:class:`TrackerDetector`
    SNI / DNS / HTTP Host strings matching a built-in list of well-known
    third-party trackers and analytics endpoints.

:class:`DohDetector`
    DNS-over-HTTPS / DNS-over-TLS / DNS-over-QUIC sessions — lookups that
    bypass the system resolver and every DNS-based detector in this tool.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, Optional, Set, Tuple

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow
from ..protocols.stealth import classify_ip

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WebRTC / STUN — IP leak
# ---------------------------------------------------------------------------

class WebRtcLeakDetector(BaseDetector):
    """
    Surface every STUN/TURN exchange and flag IP-leak responses.

    A binding success response that contains an ``XOR-MAPPED-ADDRESS``
    leaks at least the host's public IP; if the address falls in a
    private/loopback range it leaks the host's *internal* IP — the
    canonical "WebRTC IP leak" that bypasses VPN/proxy tunnelling.
    """

    @property
    def name(self) -> str:
        return "stealth_webrtc"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        stun = layer7.get("stun")
        if not stun:
            return

        msg_type = stun.get("message_type", "")
        mapped = stun.get("mapped_address")

        # --- Plain STUN traffic — informational ---
        is_request = "Request" in msg_type
        is_turn = stun.get("is_turn", False)

        evidence: Dict[str, Any] = {
            "message_type": msg_type,
            "txid": stun.get("txid"),
            "software": stun.get("software"),
            "is_turn": is_turn,
        }

        if mapped:
            leaked_ip = mapped.get("ip")
            leaked_port = mapped.get("port")
            evidence["leaked_ip"] = leaked_ip
            evidence["leaked_port"] = leaked_port
            evidence["leaked_family"] = mapped.get("family")
            evidence["leaked_attribute"] = mapped.get("attribute")

            classification = classify_ip(leaked_ip)
            evidence["leaked_address_class"] = classification

            if classification in ("private", "loopback", "link_local"):
                yield Alert(
                    alert_type=AlertType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    message=(
                        f"WebRTC leaked internal IP {leaked_ip}:{leaked_port} "
                        f"to {meta.get('dst_ip')} via STUN ({msg_type})"
                    ),
                    src_ip=meta.get("src_ip"),
                    dst_ip=meta.get("dst_ip"),
                    src_port=meta.get("src_port"),
                    dst_port=meta.get("dst_port"),
                    protocol=meta.get("protocol"),
                    rule_id="STEALTH-WEBRTC-LEAK",
                    mitre_technique="T1592.004",
                    tags=["webrtc", "ip_leak", "stealth", "fingerprint"],
                    confidence=0.95,
                    evidence=evidence,
                )
                return

            # Public-IP leak via XOR-MAPPED-ADDRESS — much milder, but the
            # browser still revealed at least the public IP to a 3rd-party
            # STUN server outside the visible tab traffic.
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.LOW,
                message=(
                    f"WebRTC reflexive address {leaked_ip}:{leaked_port} "
                    f"learned from {meta.get('src_ip')} (STUN {msg_type})"
                ),
                src_ip=meta.get("src_ip"),
                dst_ip=meta.get("dst_ip"),
                src_port=meta.get("src_port"),
                dst_port=meta.get("dst_port"),
                protocol=meta.get("protocol"),
                rule_id="STEALTH-WEBRTC-REFLEXIVE",
                mitre_technique="T1592.004",
                tags=["webrtc", "stealth", "stun"],
                confidence=0.85,
                evidence=evidence,
            )
            return

        # No mapped address — just the request side of a STUN exchange.
        if is_request:
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.LOW,
                message=(
                    f"WebRTC {msg_type} {meta.get('src_ip')} → "
                    f"{meta.get('dst_ip')}:{meta.get('dst_port')}"
                ),
                src_ip=meta.get("src_ip"),
                dst_ip=meta.get("dst_ip"),
                src_port=meta.get("src_port"),
                dst_port=meta.get("dst_port"),
                protocol=meta.get("protocol"),
                rule_id="STEALTH-WEBRTC-STUN" if not is_turn else "STEALTH-WEBRTC-TURN",
                mitre_technique="T1071",
                tags=["webrtc", "stun", "stealth"] + (["turn"] if is_turn else []),
                confidence=0.90,
                evidence=evidence,
            )


# ---------------------------------------------------------------------------
# Localhost / private-network probe (browser-side fingerprinting)
# ---------------------------------------------------------------------------

# Ports legitimately used by the OS or common apps — we don't want to
# scream every time the system talks to mDNS, dhcp, etc.
_LOCAL_QUIET_TCP_PORTS = frozenset({
    22, 53, 80, 443, 445, 548, 554, 631, 3689, 5000, 5353, 5900, 7000, 7100,
    8008, 8009, 8060, 8080, 8443, 9100,  # SSH, SMB/AFP, AirPlay, Chromecast, Roku, printers
})

_BROWSER_APPS = frozenset({
    "Safari", "Safari Technology Preview", "Google Chrome", "Google Chrome Canary",
    "Chromium", "Firefox", "Firefox Developer Edition", "Firefox Nightly", "Brave Browser",
    "Microsoft Edge", "Arc", "Opera", "Opera GX", "Vivaldi", "Orion", "Zen", "Zen Browser",
    "DuckDuckGo", "Tor Browser", "Dia", "Comet", "Yandex", "Waterfox", "LibreWolf",
})


def is_browser_app(app: str) -> bool:
    """True for web browsers, including Safari's WebKit networking process."""
    return app in _BROWSER_APPS or app.startswith("com.apple.WebKit") or app.startswith("Safari")
_LOCAL_SERVICE_SRC_PORTS = frozenset({
    53, 67, 68, 123, 137, 138, 443, 853, 1900, 3478, 5351, 5353, 5355, 19302,
})
_LOCAL_QUIET_UDP_PORTS = frozenset({
    53, 67, 68, 137, 138, 5353, 5355, 1900, 137, 5060,
})


class LocalhostProbeDetector(BaseDetector):
    """
    Flag connections directed at the user's own loopback or private-LAN
    space — the classic "website is port-scanning my machine" pattern.

    The detector treats every TCP SYN to 127.0.0.0/8 or ``::1`` as
    interesting, plus connections to RFC1918 ranges on uncommon ports.
    Repeated probes from the same source against many ports are
    upgraded to a HIGH-severity *fingerprinting* alert.
    """

    _FLAG_SYN = 0x02
    _FLAG_ACK = 0x10

    def __init__(
        self,
        scan_threshold: int = 5,
        scan_window: float = 30.0,
    ) -> None:
        self.scan_threshold = scan_threshold
        self.scan_window = scan_window
        # (src_ip, dst_ip) -> deque[(timestamp, dst_port)]
        self._history: Dict[Tuple[str, str, Optional[str]], Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=64)
        )
        self._reported: Set[Tuple[str, str, Optional[str]]] = set()
        self._udp_seen: Set[Tuple[str, str, int]] = set()

    @property
    def name(self) -> str:
        return "stealth_localhost"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dst_ip: Optional[str] = meta.get("dst_ip")
        if not dst_ip:
            return

        kind = classify_ip(dst_ip)
        if kind not in ("loopback", "private", "link_local"):
            return

        proto = meta.get("protocol")
        dst_port = meta.get("dst_port") or 0
        src_ip = meta.get("src_ip")

        # A probe originates on this machine (or the LAN).  Replies from the
        # internet to our own private address are ordinary return traffic.
        if classify_ip(src_ip) not in ("loopback", "private", "link_local"):
            return

        # Only look at the start of a connection, not every keep-alive packet.
        if proto == "tcp":
            flags = meta.get("tcp_flags", 0)
            is_initial_syn = bool(flags & self._FLAG_SYN) and not (flags & self._FLAG_ACK)
            if not is_initial_syn:
                return
            if dst_port in _LOCAL_QUIET_TCP_PORTS and kind != "loopback":
                return
        elif proto == "udp":
            if dst_port in _LOCAL_QUIET_UDP_PORTS:
                return
            # Replies from local services (the router's DNS, NTP, SSDP …).
            if (meta.get("src_port") or 0) in _LOCAL_SERVICE_SRC_PORTS:
                return
            # UDP has no handshake: report each (src, dst, port) only once.
            udp_key = (src_ip, dst_ip, dst_port)
            if udp_key in self._udp_seen:
                return
            self._udp_seen.add(udp_key)
            if len(self._udp_seen) > 50_000:
                self._udp_seen.clear()
        else:
            return

        # Who opened the connection (set by the engine's enricher, if any).
        app = (layer7.get("context") or {}).get("app")
        browser = app is None or is_browser_app(app)
        who = f"{app} ({src_ip})" if app else src_ip

        # Single-probe events are reported for browsers (and unknown owners):
        # native apps talk to their own localhost helpers all the time.
        sev = Severity.HIGH if kind == "loopback" else Severity.MEDIUM
        if browser:
            yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=sev,
                message=(
                    f"{proto.upper()} probe to {kind} address {dst_ip}:{dst_port} "
                    f"from {who} (browser/local-software fingerprinting?)"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=meta.get("src_port"),
                dst_port=dst_port,
                protocol=proto,
                rule_id="STEALTH-LOCALHOST-PROBE",
                mitre_technique="T1046",
                tags=["localhost_probe", "stealth", "fingerprint", kind],
                confidence=0.85 if kind == "loopback" else 0.65,
                evidence={
                    "destination_class": kind,
                    "destination_port": dst_port,
                    "transport": proto,
                },
            )

        # Track the per-(source, target, app) port spread for a scan alert.
        # Keying on the app matters on loopback, where every local program
        # shares 127.0.0.1 as both source and destination.
        if not src_ip:
            return
        now = meta.get("timestamp", time.time())
        key = (src_ip, dst_ip, app)
        hist = self._history[key]
        # Expire stale samples.
        while hist and (now - hist[0][0]) > self.scan_window:
            hist.popleft()
        hist.append((now, dst_port))
        unique_ports = {p for _, p in hist}
        if len(unique_ports) >= self.scan_threshold and key not in self._reported:
            self._reported.add(key)
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.CRITICAL if browser else Severity.HIGH,
                message=(
                    f"Localhost port scan: {who} probed {len(unique_ports)} "
                    f"ports on {dst_ip} in {self.scan_window:.0f}s — "
                    + ("likely browser-side fingerprinting" if browser
                       else "unusual for a local app")
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                rule_id="STEALTH-LOCALHOST-SCAN",
                mitre_technique="T1046",
                tags=["localhost_scan", "stealth", "fingerprint"],
                confidence=0.95,
                evidence={
                    "ports_probed": sorted(unique_ports),
                    "port_count": len(unique_ports),
                    "window_seconds": self.scan_window,
                },
            )


# ---------------------------------------------------------------------------
# QUIC / HTTP/3
# ---------------------------------------------------------------------------

class QuicHttp3Detector(BaseDetector):
    """Surface QUIC Initial packets — every HTTP/3 session starts here."""

    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str, int]] = set()

    @property
    def name(self) -> str:
        return "stealth_quic"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        quic = layer7.get("quic")
        if not quic or quic.get("packet_type") != "Initial":
            return
        # A decrypted Initial whose ClientHello continues in the next packet:
        # wait for the packet that completes it so the alert carries the SNI.
        if quic.get("decrypted") and not quic.get("client_hello_complete"):
            return
        # Server → client Initials (the reply half of the handshake) can't be
        # decrypted with client keys; they are not new connections.
        if not quic.get("decrypted") and (meta.get("src_port") or 0) in (443, 8443):
            return

        src = meta.get("src_ip")
        dst = meta.get("dst_ip")
        port = meta.get("dst_port") or 0
        if not src or not dst:
            return
        sni = quic.get("sni")
        # One event per site, not per CDN edge IP (video sites rotate many).
        key = (src, sni, 0) if sni else (src, dst, port)
        if key in self._seen:
            return
        self._seen.add(key)
        if len(self._seen) > 100_000:
            self._seen.clear()

        target = f"{sni} ({dst}:{port})" if sni else f"{dst}:{port}"
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message=(
                f"QUIC/HTTP-3 connection {src} → {target} ({quic.get('version')})"
            ),
            src_ip=src,
            dst_ip=dst,
            src_port=meta.get("src_port"),
            dst_port=port,
            protocol="udp",
            rule_id="STEALTH-QUIC-INITIAL",
            mitre_technique="T1071.001",
            tags=["quic", "http3", "stealth"],
            confidence=0.95,
            evidence={
                "version": quic.get("version"),
                "dcid": quic.get("dcid"),
                "scid": quic.get("scid"),
                "sni": sni,
                "alpn": quic.get("alpn"),
                "ech": quic.get("ech", False),
            },
        )


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

class WebSocketDetector(BaseDetector):
    """Flag WebSocket Upgrade handshakes (live in DevTools' WS sub-tab)."""

    @property
    def name(self) -> str:
        return "stealth_websocket"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        http = layer7.get("http") or {}
        if not http.get("websocket_upgrade"):
            return

        host = http.get("host") or ""
        uri = http.get("uri") or ""
        ua = http.get("user_agent") or ""
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message=(
                f"WebSocket upgrade to {host}{uri} from {meta.get('src_ip')}"
            ),
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            src_port=meta.get("src_port"),
            dst_port=meta.get("dst_port"),
            protocol="tcp",
            rule_id="STEALTH-WEBSOCKET",
            mitre_technique="T1071.001",
            tags=["websocket", "stealth"],
            confidence=0.99,
            evidence={
                "host": host,
                "path": uri,
                "user_agent": ua[:120],
            },
        )


# ---------------------------------------------------------------------------
# sendBeacon / pixel trackers
# ---------------------------------------------------------------------------

class BeaconDetector(BaseDetector):
    """Flag fire-and-forget HTTP requests typical of analytics beacons."""

    @property
    def name(self) -> str:
        return "stealth_beacon"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        http = layer7.get("http") or {}
        if not http.get("beacon_suspect"):
            return

        host = http.get("host") or ""
        uri = http.get("uri") or ""
        method = http.get("method") or ""
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message=f"Beacon/pixel {method} {host}{uri} from {meta.get('src_ip')}",
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            src_port=meta.get("src_port"),
            dst_port=meta.get("dst_port"),
            protocol="tcp",
            rule_id="STEALTH-BEACON",
            mitre_technique="T1071.001",
            tags=["beacon", "tracking", "stealth"],
            confidence=0.75,
            evidence={
                "host": host,
                "path": uri,
                "method": method,
                "content_type": (http.get("headers") or {}).get("content-type"),
                "content_length": http.get("content_length"),
            },
        )


# ---------------------------------------------------------------------------
# DNS prefetch / preconnect storms
# ---------------------------------------------------------------------------

class DnsPrefetchDetector(BaseDetector):
    """
    Detect bursts of unique DNS lookups from one source — the fingerprint
    of ``<link rel="dns-prefetch">`` and ``<link rel="preconnect">``
    hints firing the moment a page starts loading.
    """

    def __init__(
        self,
        burst_threshold: int = 8,
        window_seconds: float = 5.0,
    ) -> None:
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        # src_ip → deque[(timestamp, query_name)]
        self._history: Dict[str, Deque[Tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=64)
        )
        self._last_alert: Dict[str, float] = {}

    @property
    def name(self) -> str:
        return "stealth_dns_prefetch"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dns = layer7.get("dns")
        if not dns:
            return
        if dns.get("is_response"):
            return
        name = dns.get("query_name")
        src = meta.get("src_ip")
        if not name or not src:
            return

        now = meta.get("timestamp", time.time())
        hist = self._history[src]
        while hist and (now - hist[0][0]) > self.window_seconds:
            hist.popleft()
        hist.append((now, name))

        unique = {n for _, n in hist}
        if len(unique) < self.burst_threshold:
            return
        # Cool-down to avoid alert flooding while the burst is ongoing.
        if (now - self._last_alert.get(src, 0.0)) < self.window_seconds:
            return
        self._last_alert[src] = now

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message=(
                f"DNS prefetch storm: {src} resolved {len(unique)} unique "
                f"hosts in {self.window_seconds:.0f}s "
                f"(rel=dns-prefetch / preconnect)"
            ),
            src_ip=src,
            protocol="udp",
            rule_id="STEALTH-DNS-PREFETCH",
            mitre_technique="T1071.004",
            tags=["dns_prefetch", "stealth", "page_load"],
            confidence=0.70,
            evidence={
                "unique_hosts": sorted(unique)[:20],
                "host_count": len(unique),
                "window_seconds": self.window_seconds,
            },
        )


# ---------------------------------------------------------------------------
# 3rd-party tracker / analytics endpoints
# ---------------------------------------------------------------------------

# A modest curated list — tuned to be visibly useful without being
# academic.  Domains are *suffix-matched*: an entry like ``doubleclick.net``
# matches ``stats.g.doubleclick.net`` but not ``notdoubleclick.net``.
_TRACKER_DOMAINS: Dict[str, str] = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google DoubleClick",
    "googlesyndication.com": "Google AdSense",
    "googleadservices.com": "Google Ads",
    "facebook.net": "Meta Pixel",
    "facebook.com": "Meta",
    "fbcdn.net": "Meta CDN",
    "connect.facebook.net": "Meta Pixel",
    "scorecardresearch.com": "ComScore",
    "quantserve.com": "Quantcast",
    "criteo.com": "Criteo",
    "criteo.net": "Criteo",
    "adsrvr.org": "The Trade Desk",
    "rubiconproject.com": "Magnite",
    "pubmatic.com": "PubMatic",
    "adnxs.com": "Xandr",
    "amazon-adsystem.com": "Amazon Ads",
    "taboola.com": "Taboola",
    "outbrain.com": "Outbrain",
    "hotjar.com": "Hotjar",
    "fullstory.com": "FullStory",
    "mouseflow.com": "Mouseflow",
    "smartlook.com": "Smartlook",
    "logrocket.com": "LogRocket",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "heap.io": "Heap",
    "heapanalytics.com": "Heap",
    "appsflyer.com": "AppsFlyer",
    "branch.io": "Branch",
    "adjust.com": "Adjust",
    "kochava.com": "Kochava",
    "tiktokcdn.com": "TikTok",
    "tiktok.com": "TikTok",
    "bytedance.com": "ByteDance",
    "bat.bing.com": "Microsoft UET",
    "clarity.ms": "Microsoft Clarity",
    "linkedin.com": "LinkedIn Insight",
    "licdn.com": "LinkedIn",
    "snapchat.com": "Snap Pixel",
    "sc-static.net": "Snap",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "datadoghq.com": "Datadog RUM",
    "sentry.io": "Sentry",
    "ingest.sentry.io": "Sentry",
    "intercom.io": "Intercom",
    "intercomcdn.com": "Intercom",
    "cloudflareinsights.com": "Cloudflare RUM",
    "hubspot.com": "HubSpot",
    "hs-analytics.net": "HubSpot",
    "hsforms.net": "HubSpot Forms",
    "salesforce.com": "Salesforce",
    "marketo.com": "Marketo",
    "pardot.com": "Pardot",
    "demdex.net": "Adobe Audience",
    "omtrdc.net": "Adobe Analytics",
    "everesttech.net": "Adobe Advertising",
    "2o7.net": "Adobe Analytics",
    "addthis.com": "AddThis",
    "yandex.ru": "Yandex Metrica",
    "mc.yandex.ru": "Yandex Metrica",
    "mc.yandex.com": "Yandex Metrica",
    "alipay.com": "Alipay",
    "alipayobjects.com": "Alipay",
}


class TrackerDetector(BaseDetector):
    """
    Flag connections to known third-party tracker / analytics domains.

    Looks at three signal sources:

    1. DNS query names
    2. TLS Server Name Indication (SNI)
    3. HTTP ``Host`` headers
    """

    def __init__(
        self,
        domains: Optional[Dict[str, str]] = None,
        extra_domains: Optional[Dict[str, str]] = None,
    ) -> None:
        # Built-in labels win over the (much larger) Disconnect feed because
        # they are hand-curated product names.
        self.domains: Dict[str, str] = dict(extra_domains or {})
        self.domains.update(domains or _TRACKER_DOMAINS)
        self._reported: Set[Tuple[str, str]] = set()

    @property
    def name(self) -> str:
        return "stealth_trackers"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        host: Optional[str] = None
        source = ""

        if "tls" in layer7 and layer7["tls"].get("sni"):
            host = layer7["tls"]["sni"]
            source = "TLS SNI"
        elif "quic" in layer7 and layer7["quic"].get("sni"):
            host = layer7["quic"]["sni"]
            source = "QUIC SNI"
        elif "http" in layer7 and layer7["http"].get("host"):
            host = layer7["http"]["host"]
            source = "HTTP Host"
        elif "dns" in layer7 and layer7["dns"].get("query_name") and not layer7["dns"].get("is_response"):
            host = layer7["dns"]["query_name"]
            source = "DNS"

        if not host:
            return
        host_lower = host.lower().rstrip(".")

        match = self._match(host_lower)
        if not match:
            return
        category, suffix = match
        src = meta.get("src_ip") or "?"
        key = (src, host_lower)
        if key in self._reported:
            return
        self._reported.add(key)

        invasive = "Cryptomining" in category or "FingerprintingInvasive" in category
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.MEDIUM if invasive else Severity.LOW,
            message=f"3rd-party tracker: {host_lower} ({category}) via {source}",
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            src_port=meta.get("src_port"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            rule_id="STEALTH-TRACKER",
            mitre_technique="T1071.001",
            tags=["tracker", "analytics", "privacy", "stealth"],
            confidence=0.95,
            evidence={
                "host": host_lower,
                "category": category,
                "matched_suffix": suffix,
                "source": source,
            },
        )

    def _match(self, host: str) -> Optional[Tuple[str, str]]:
        # Walk label suffixes, most specific first: a.b.example.com,
        # b.example.com, example.com, com.
        candidate = host
        while True:
            category = self.domains.get(candidate)
            if category is not None:
                return category, candidate
            dot = candidate.find(".")
            if dot < 0:
                return None
            candidate = candidate[dot + 1:]


# ---------------------------------------------------------------------------
# Encrypted DNS (DoH / DoT / DoQ)
# ---------------------------------------------------------------------------

# A small built-in set so detection works before any feed is downloaded.
_DOH_HOSTS: Set[str] = {
    "dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net",
    "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "doh.mullvad.net", "dns.mullvad.net",
    "dns.controld.com", "freedns.controld.com", "dns0.eu", "zero.dns0.eu",
    "ordns.he.net", "doh.libredns.gr", "doh.xfinity.com", "dns.twnic.tw",
    "doh.applied-privacy.net", "doh.ffmuc.net", "dns.switch.ch",
}
_DOH_IPS: Set[str] = {
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.11", "149.112.112.11",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    "45.90.28.0", "45.90.30.0", "185.228.168.9", "185.228.169.9", "76.76.2.0",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
}


class DohDetector(BaseDetector):
    """
    Surface encrypted DNS that bypasses the operating system's resolver.

    Browsers increasingly ship their own DNS-over-HTTPS client ("Secure
    DNS" in Chrome, "DNS over HTTPS" in Firefox).  Those lookups never
    reach port 53, so the DNS tunnelling, prefetch, tracker-by-DNS, and
    threat-intel domain checks cannot see them.  This detector reports
    each new encrypted-DNS session so the blind spot is visible.

    Signals:

    * TLS / QUIC SNI or a plaintext DNS lookup naming a known DoH resolver
    * TCP or UDP port 853 (DNS-over-TLS / DNS-over-QUIC)
    * HTTPS (443) to a known public resolver IP
    """

    def __init__(
        self,
        hosts: Optional[Set[str]] = None,
        ips: Optional[Set[str]] = None,
    ) -> None:
        self.hosts: Set[str] = set(_DOH_HOSTS) | set(hosts or ())
        self.ips: Set[str] = set(_DOH_IPS) | set(ips or ())
        self._reported: Set[Tuple[str, str, str]] = set()

    @property
    def name(self) -> str:
        return "stealth_doh"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        src = meta.get("src_ip")
        dst = meta.get("dst_ip")
        dst_port = meta.get("dst_port") or 0
        proto = meta.get("protocol")
        if not src or not dst or proto not in ("tcp", "udp"):
            return

        sni = (layer7.get("tls") or {}).get("sni") or (layer7.get("quic") or {}).get("sni")
        dns_name = None
        dns = layer7.get("dns") or {}
        if dns and not dns.get("is_response"):
            dns_name = dns.get("query_name")

        method = ""
        resolver = ""
        if sni and sni.lower().rstrip(".") in self.hosts:
            method = "DoH (DNS-over-HTTPS)" if dst_port != 853 else "DoT (DNS-over-TLS)"
            resolver = sni.lower()
        elif dst_port == 853:
            method = "DoT (DNS-over-TLS)" if proto == "tcp" else "DoQ (DNS-over-QUIC)"
            resolver = dst
        elif dst_port == 443 and dst in self.ips:
            method = "DoH (DNS-over-HTTPS)"
            resolver = dst
        elif dns_name and dns_name.lower().rstrip(".") in self.hosts:
            method = "DoH bootstrap lookup"
            resolver = dns_name.lower().rstrip(".")
        else:
            return

        key = (src, resolver, method)
        if key in self._reported:
            return
        self._reported.add(key)

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.MEDIUM if "bootstrap" not in method else Severity.LOW,
            message=(
                f"Encrypted DNS: {method} from {src} to {resolver} — "
                f"these lookups bypass the system resolver and DNS monitoring"
            ),
            src_ip=src,
            dst_ip=dst,
            src_port=meta.get("src_port"),
            dst_port=dst_port,
            protocol=proto,
            rule_id="STEALTH-ENCRYPTED-DNS",
            mitre_technique="T1071.004",
            tags=["doh", "encrypted_dns", "stealth", "evasion"],
            confidence=0.9 if sni or dst_port == 853 else 0.7,
            evidence={
                "method": method,
                "resolver": resolver,
                "resolver_ip": dst,
                "sni": sni,
            },
        )
