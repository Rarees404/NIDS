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
    22, 53, 80, 443, 445, 631, 5353, 5900, 8080, 8443,
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
        self._history: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=64)
        )
        self._reported: Set[Tuple[str, str]] = set()

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
        else:
            return

        # First-class single event — every loopback connection is interesting.
        sev = Severity.HIGH if kind == "loopback" else Severity.MEDIUM
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=sev,
            message=(
                f"{proto.upper()} probe to {kind} address {dst_ip}:{dst_port} "
                f"from {src_ip} (browser/local-software fingerprinting?)"
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

        # Track the per-pair port spread for a multi-port scan alert.
        if not src_ip:
            return
        now = meta.get("timestamp", time.time())
        key = (src_ip, dst_ip)
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
                severity=Severity.CRITICAL,
                message=(
                    f"Localhost port scan: {src_ip} probed {len(unique_ports)} "
                    f"ports on {dst_ip} in {self.scan_window:.0f}s — "
                    f"likely browser-side fingerprinting"
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

        src = meta.get("src_ip")
        dst = meta.get("dst_ip")
        port = meta.get("dst_port") or 0
        if not src or not dst:
            return
        key = (src, dst, port)
        if key in self._seen:
            return
        self._seen.add(key)

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message=(
                f"QUIC/HTTP-3 connection {src} → {dst}:{port} ({quic.get('version')})"
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
    ) -> None:
        self.domains = domains or _TRACKER_DOMAINS
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

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
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
        for suffix, category in self.domains.items():
            if host == suffix or host.endswith("." + suffix):
                return category, suffix
        return None
