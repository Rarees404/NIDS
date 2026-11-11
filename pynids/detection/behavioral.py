"""
Behavioral / heuristic detection for PyNIDS.

Whereas signature detection requires exact pattern matches and anomaly
detection reacts to statistical outliers, behavioral detection models
*sequences of actions* that collectively indicate malicious intent.

Detectors
---------
DnsTunnelingDetector
    Identifies DNS queries used as covert data-exfiltration channels.
    High Shannon entropy and/or abnormally long subdomain labels are
    characteristic of DNS tunneling tools (iodine, dnscat2, DNScat).
    MITRE: T1071.004.

DgaDetector
    Counts failed lookups (NXDOMAIN) for many different domains from one
    client.  Malware with a domain-generation algorithm tries dozens of
    throwaway names until one resolves.
    MITRE: T1568.002.

HttpAttackDetector
    Leverages the HTTP dissector's heuristic flags (SQL injection,
    XSS, path traversal, scanner user-agents) to generate severity-
    graded alerts for web application attacks.
    MITRE: T1190.

DataExfiltrationDetector
    Watches per-flow outbound byte counts.  When a single flow
    transfers an unusually large amount of data to an external host,
    an alert is raised for analyst review.
    MITRE: T1041.

BeaconingDetector
    Identifies C2 beaconing by analysing the regularity of connection
    intervals between the same source/destination pair.  Beaconing
    malware sends periodic check-ins at nearly constant intervals.
    Low coefficient of variation (stddev/mean) over several samples
    indicates automated, machine-generated traffic.
    MITRE: T1071.
"""
from __future__ import annotations

import logging
import math
import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow
from ..protocols.stealth import classify_ip


# Destinations that are never interesting for scan / beacon heuristics:
# multicast service discovery (mDNS, SSDP, vendor discovery) and broadcasts.
def _is_multicast_or_broadcast(ip: Optional[str]) -> bool:
    if not ip:
        return False
    if ip == "255.255.255.255" or ip.endswith(".255"):
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def _is_loopback(ip: Optional[str]) -> bool:
    return bool(ip) and (ip.startswith("127.") or ip == "::1")


# Real-time media relays (WebRTC STUN/TURN): calls legitimately push
# hundreds of MB upstream.
_MEDIA_PORTS = frozenset({3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309})
# Periodic OS housekeeping that is regular by design.
_SYSTEM_SERVICE_PORTS = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353, 5355})

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

# Two-label public suffixes common enough to matter for "registered domain".
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "com.tr", "co.za",
    "co.in", "co.kr", "com.sg", "com.hk", "com.tw", "com.ar", "co.il",
})
# Provider zones whose hostnames are random by design (ad frames, CDN
# nodes, cloud endpoints).  Tunnelling needs an authoritative name server
# the attacker controls, which these zones never delegate.
_RANDOM_NAME_ZONES = frozenset({
    "googlesyndication.com", "googlevideo.com", "1e100.net", "gvt1.com", "gvt2.com",
    "akamaiedge.net", "akamai.net", "akamaihd.net", "edgekey.net", "cloudfront.net",
    "amazonaws.com", "azureedge.net", "trafficmanager.net", "fastly.net", "llnwd.net",
})
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _registered_domain(labels: List[str]) -> int:
    """Number of trailing labels forming the registered domain (eTLD+1, approximated)."""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return 3
    return min(2, len(labels))


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts: Dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _class_switches(text: str) -> int:
    """Letter↔digit transitions: encoded data mixes them, words and names rarely do."""
    switches, prev = 0, None
    for ch in text:
        kind = "d" if ch.isdigit() else "a" if ch.isalpha() else None
        if kind and prev and kind != prev:
            switches += 1
        if kind:
            prev = kind
    return switches


class DnsTunnelingDetector(BaseDetector):
    """
    Detect DNS-based covert channels by looking at the labels a tunnel
    would encode data into.

    Only queries are judged (a response repeats the question, which would
    double every alert).  Reverse lookups (``in-addr.arpa`` / ``ip6.arpa``),
    mDNS / DNS-SD (``.local``, ``_tcp`` / ``_udp`` service labels) and
    provider zones with random-by-design names are skipped.

    A query is suspicious when, below its registered domain:

    * a label of at least ``label_min_length`` characters has Shannon
      entropy >= ``entropy_threshold`` and mixes letters and digits the way
      base32 / hex / base64 encodings do, or
    * the subdomain part is at least ``length_threshold`` characters long.

    Additionally, ``unique_subdomain_threshold`` distinct subdomains of one
    registered domain within ``unique_window`` seconds (0 disables) flags a
    tunnel that keeps each query short.

    Args:
        entropy_threshold: Minimum entropy (bits/char) of an encoded-looking label (default 3.5).
        length_threshold:  Minimum length of the subdomain part (default 50).
        depth_threshold:   Label count reported in the evidence when reached (default 5).
    """

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        depth_threshold: int = 5,
        label_min_length: int = 16,
        unique_subdomain_threshold: int = 50,
        unique_window: float = 60.0,
        ignore_domains: Iterable[str] = (),
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.depth_threshold = depth_threshold
        self.label_min_length = label_min_length
        self.unique_subdomain_threshold = unique_subdomain_threshold
        self.unique_window = unique_window
        self.ignore_domains = _RANDOM_NAME_ZONES | {d.lower().strip(".") for d in ignore_domains if d}
        # registered domain -> (window start, distinct subdomains, alerted)
        self._subdomains: Dict[str, list] = {}

    @property
    def name(self) -> str:
        return "dns_tunneling"

    def prune(self, now: float) -> None:
        for dom in [d for d, st in self._subdomains.items() if now - st[0] > self.unique_window]:
            del self._subdomains[dom]

    def _ignored(self, name: str, labels: List[str]) -> bool:
        if name.endswith((".in-addr.arpa", ".ip6.arpa")) or name.endswith(".local"):
            return True
        if any(lbl in ("_tcp", "_udp") for lbl in labels):
            return True  # DNS-SD service discovery
        return any(name == z or name.endswith("." + z) for z in self.ignore_domains)

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dns = layer7.get("dns")
        if not dns or dns.get("is_response"):
            return

        query_name: Optional[str] = dns.get("query_name")
        if not query_name:
            return
        name = query_name.lower().rstrip(".")
        labels = [lbl for lbl in name.split(".") if lbl]
        if not labels or self._ignored(name, labels):
            return

        reg_len = _registered_domain(labels)
        registered = ".".join(labels[-reg_len:])
        # Data is encoded below the registered domain; a bare domain is judged by its own label.
        sub_labels = [lbl for lbl in labels[:-reg_len] if not lbl.startswith("_")] or labels[:1]
        subdomain = ".".join(labels[:-reg_len])
        # Judge every label: one long plain label must not hide an encoded one next to it.
        encoded = [lbl for lbl in sub_labels if self._looks_encoded(lbl)]
        longest = max(encoded or sub_labels, key=lambda lbl: (len(lbl), _shannon(lbl)))
        entropy = _shannon(longest)
        depth = len(labels) - 1

        triggered_reasons: List[str] = []
        if encoded:
            triggered_reasons.append(f"encoded-looking label ({len(longest)} chars, entropy={entropy:.2f})")
        if len(subdomain) >= self.length_threshold:
            triggered_reasons.append(f"subdomain length={len(subdomain)}")
        unique = self._count_unique(registered, subdomain, meta.get("timestamp") or time.time())
        if unique is not None:
            triggered_reasons.append(f"{unique} distinct subdomains in {self.unique_window:.0f}s")

        if not triggered_reasons:
            return
        if depth >= self.depth_threshold:
            triggered_reasons.append(f"depth={depth}")

        confidence = min(
            1.0,
            (
                (entropy / self.entropy_threshold if entropy >= self.entropy_threshold else 0)
                + (len(subdomain) / self.length_threshold if len(subdomain) >= self.length_threshold else 0)
                + (1.0 if unique is not None else 0)
            ) / 2.0,
        )

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.HIGH,
            message=(
                f"Possible DNS tunneling from {meta.get('src_ip')}: "
                f"query '{query_name}' ({', '.join(triggered_reasons)})"
            ),
            src_ip=meta.get("src_ip"),
            dst_ip=meta.get("dst_ip"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            mitre_technique="T1071.004",
            tags=["dns_tunneling", "exfiltration", "covert_channel"],
            confidence=confidence,
            evidence={
                "query_name": query_name,
                "registered_domain": registered,
                "longest_label": longest,
                "entropy": round(entropy, 3),
                "name_length": len(name),
                "subdomain_length": len(subdomain),
                "subdomain_depth": depth,
                "distinct_subdomains": unique,
            },
        )

    def _looks_encoded(self, label: str) -> bool:
        return (len(label) >= self.label_min_length
                and _shannon(label) >= self.entropy_threshold
                and _class_switches(label) >= max(3, len(label) // 6)
                and not _GUID_RE.match(label))

    def _count_unique(self, registered: str, subdomain: str, now: float) -> Optional[int]:
        """Track distinct subdomains per registered domain; returns the count once it crosses the threshold."""
        if not self.unique_subdomain_threshold or not subdomain:
            return None
        state = self._subdomains.get(registered)
        if state is None or now - state[0] > self.unique_window:
            if state is None and len(self._subdomains) >= 10_000:
                del self._subdomains[next(iter(self._subdomains))]
            state = self._subdomains[registered] = [now, set(), False]
        seen: set = state[1]
        if len(seen) <= self.unique_subdomain_threshold:
            seen.add(subdomain)
        if state[2] or len(seen) < self.unique_subdomain_threshold:
            return None
        state[2] = True  # once per domain per window
        return len(seen)


# ---------------------------------------------------------------------------
# Domain-generation algorithms (NXDOMAIN bursts)
# ---------------------------------------------------------------------------

class DgaDetector(BaseDetector):
    """
    Flag a client whose lookups keep failing for many *different* domains.

    Malware that finds its command server through a domain-generation
    algorithm asks for dozens of pseudo-random names; almost all of them do
    not exist, so the resolver answers NXDOMAIN again and again.  A typo or a
    dead bookmark fails for one domain; an app retrying one broken name fails
    for one domain many times.  Only distinct registered domains count.

    Skipped: single-label names (search-suffix expansion, Chrome's random
    start-up probes), ``.local`` / ``.arpa`` / ``.lan`` / ``.home`` style
    private zones, and service-discovery names.

    Args:
        nxdomain_threshold: Distinct failing registered domains that trigger an alert.
        window:             Sliding window in seconds.
    """

    _PRIVATE_SUFFIXES = (".local", ".arpa", ".lan", ".home", ".internal", ".corp", ".localdomain",
                         ".intranet", ".test", ".invalid", ".example")

    def __init__(self, nxdomain_threshold: int = 12, window: float = 60.0) -> None:
        self.nxdomain_threshold = nxdomain_threshold
        self.window = window
        # client ip -> deque[(timestamp, registered domain, full name)]
        self._failures: Dict[str, Deque[Tuple[float, str, str]]] = defaultdict(deque)
        self._alerted: Dict[str, float] = {}

    @property
    def name(self) -> str:
        return "dga"

    def prune(self, now: float) -> None:
        for client in [c for c, d in self._failures.items() if not d or now - d[-1][0] > self.window]:
            del self._failures[client]
        self._alerted = {c: t for c, t in self._alerted.items() if now - t <= self.window}

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        dns = layer7.get("dns")
        if not dns or not dns.get("is_response") or dns.get("rcode") != 3:
            return
        if not self.nxdomain_threshold:
            return
        query_name: Optional[str] = dns.get("query_name")
        client = meta.get("dst_ip")  # the answer travels resolver → client
        if not query_name or not client:
            return
        name = query_name.lower().rstrip(".")
        labels = [lbl for lbl in name.split(".") if lbl]
        if len(labels) < 2 or name.endswith(self._PRIVATE_SUFFIXES):
            return
        if any(lbl.startswith("_") for lbl in labels):
            return
        registered = ".".join(labels[-_registered_domain(labels):])

        ts = meta.get("timestamp") or time.time()
        bucket = self._failures[client]
        while bucket and ts - bucket[0][0] > self.window:
            bucket.popleft()
        bucket.append((ts, registered, name))
        if len(bucket) > 2000:
            bucket.popleft()

        domains = {entry[1] for entry in bucket}
        if len(domains) < self.nxdomain_threshold:
            return
        if ts - self._alerted.get(client, -1e18) <= self.window:
            return
        self._alerted[client] = ts

        # Generated names look random; dead-but-real names look like words.
        firsts = [d.split(".")[0] for d in domains]
        mean_entropy = sum(_shannon(lbl) for lbl in firsts) / len(firsts)
        mean_length = sum(len(lbl) for lbl in firsts) / len(firsts)
        random_looking = mean_entropy >= 3.0 and mean_length >= 10
        context = layer7.get("context") or {}
        who = context.get("app") or client
        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.HIGH if random_looking else Severity.MEDIUM,
            message=(
                f"Many failed DNS lookups: {who} asked for {len(domains)} different domains that "
                f"do not exist in {self.window:.0f}s"
                + (" — the names look machine-generated" if random_looking else "")
            ),
            src_ip=client,
            dst_ip=meta.get("src_ip"),
            dst_port=meta.get("src_port"),
            protocol=meta.get("protocol"),
            mitre_technique="T1568.002",
            tags=["dga", "dns", "c2"],
            confidence=min(1.0, (0.45 if random_looking else 0.25)
                           + len(domains) / (self.nxdomain_threshold * 4)),
            evidence={
                "failed_domains": len(domains),
                "failed_lookups": len(bucket),
                "window_seconds": self.window,
                "sample_names": sorted({entry[2] for entry in bucket})[:15],
                "mean_label_entropy": round(mean_entropy, 2),
                "mean_label_length": round(mean_length, 1),
                "looks_generated": random_looking,
                "resolver": meta.get("src_ip"),
            },
        )


# ---------------------------------------------------------------------------
# HTTP attack patterns
# ---------------------------------------------------------------------------

class HttpAttackDetector(BaseDetector):
    """
    Raise alerts for HTTP-layer attack heuristics detected by the dissector.

    Each heuristic (SQLi, XSS, path traversal, scanner) maps to a
    distinct alert with an appropriate severity level and MITRE reference.
    """

    @property
    def name(self) -> str:
        return "http_attacks"

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        http = layer7.get("http")
        if not http:
            return
        # Attacks travel client → server.  A server's response (an HTML page
        # full of <script> tags) or traffic flowing back on a connection the
        # other side opened is not an attack by this source.
        if http.get("direction") == "response":
            return
        src_ip = meta.get("src_ip")
        # A parsed request line already proves this side is the client.  Flow
        # direction is only "first packet seen", which is wrong for connections
        # already open when capture (re)started, so it only judges the rest.
        if (http.get("direction") != "request" and flow is not None
                and flow.src_ip and flow.src_ip != src_ip):
            return

        dst_ip = meta.get("dst_ip")
        dst_port = meta.get("dst_port")
        uri = http.get("uri", "")

        if http.get("sqli_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.CRITICAL,
                message=f"SQL injection attempt from {src_ip} → {dst_ip}{uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1190",
                tags=["sqli", "webapp", "initial_access"],
                confidence=0.85,
                evidence={"uri": uri, "method": http.get("method"), "host": http.get("host")},
            )

        if http.get("xss_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.HIGH,
                message=f"XSS attempt from {src_ip} → {dst_ip}{uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1059.007",
                tags=["xss", "webapp"],
                confidence=0.80,
                evidence={"uri": uri, "method": http.get("method")},
            )

        if http.get("path_traversal_suspect"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.HIGH,
                message=f"Path traversal attempt from {src_ip}: {uri}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1083",
                tags=["path_traversal", "webapp"],
                confidence=0.80,
                evidence={"uri": uri},
            )

        if http.get("scanner_ua"):
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=Severity.LOW,
                message=(
                    f"Known scanner user-agent from {src_ip}: "
                    f"{http.get('user_agent', '')[:80]}"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
                mitre_technique="T1595",
                tags=["scanner", "recon"],
                confidence=0.95,
                evidence={
                    "user_agent": http.get("user_agent"),
                    "uri": uri,
                    "method": http.get("method"),
                },
            )


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

class DataExfiltrationDetector(BaseDetector):
    """
    Flag flows that transfer an unusually large volume of data outbound.

    Counts only bytes sent *by the connection's initiator* (uploads from
    this machine), never downloads, and ignores WebRTC call media relays.

    Args:
        threshold_bytes: Outbound byte count that triggers an alert (default 100 MiB).
    """

    _DEFAULT_THRESHOLD = 100 * 1024 * 1024  # 100 MiB

    def __init__(self, threshold_bytes: int = _DEFAULT_THRESHOLD) -> None:
        self.threshold_bytes = threshold_bytes
        self._alerted_flows: set = set()

    @property
    def name(self) -> str:
        return "data_exfiltration"

    def prune(self, now: float) -> None:
        # Flow IDs of long-finished uploads; a re-alert after this is harmless.
        if len(self._alerted_flows) > 50_000:
            self._alerted_flows.clear()

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        if flow is None:
            return

        if flow.bytes_from_src < self.threshold_bytes:
            return
        if flow.flow_id in self._alerted_flows:
            return
        if flow.dst_port in _MEDIA_PORTS or flow.src_port in _MEDIA_PORTS:
            return

        self._alerted_flows.add(flow.flow_id)
        mb = flow.bytes_from_src / (1024 * 1024)

        yield Alert(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.MEDIUM,
            message=(
                f"Large upload: {flow.src_ip} → {flow.dst_ip}:{flow.dst_port} "
                f"transferred {mb:.1f} MiB"
            ),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            flow_id=flow.flow_id,
            mitre_technique="T1041",
            tags=["exfiltration", "data_transfer"],
            confidence=0.70,
            evidence={
                "bytes_transferred": flow.bytes_from_src,
                "megabytes": round(mb, 2),
                "packet_count": flow.packet_count,
                "duration_seconds": round(flow.duration, 2),
                "avg_packet_size_bytes": round(flow.avg_packet_size, 2),
            },
        )


# ---------------------------------------------------------------------------
# C2 beaconing
# ---------------------------------------------------------------------------

class BeaconingDetector(BaseDetector):
    """
    Identify C2 beaconing via inter-arrival time regularity analysis.

    For each (src_ip, dst_ip, dst_port) tuple, the detector records the
    timestamps of connection events.  Once a minimum number of samples
    is collected, the coefficient of variation (CV = stddev/mean) of the
    inter-arrival intervals is computed.  A very low CV indicates highly
    regular, automated traffic consistent with beaconing malware.

    Args:
        min_connections:         Minimum events before analysis is performed.
        cv_threshold:            CV below this value triggers an alert (default 0.2).
        max_interval_seconds:    Ignore intervals longer than this (connection gaps).
    """

    def __init__(
        self,
        min_connections: int = 6,
        cv_threshold: float = 0.20,
        max_interval_seconds: float = 3600.0,
    ) -> None:
        self.min_connections = min_connections
        self.cv_threshold = cv_threshold
        self.max_interval_seconds = max_interval_seconds
        # {(src_ip, dst_ip, dst_port) → deque[timestamps]}
        self._history: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(
            lambda: deque(maxlen=30)
        )
        self._alerted: set = set()

    @property
    def name(self) -> str:
        return "beaconing"

    def prune(self, now: float) -> None:
        # Gaps longer than max_interval_seconds are ignored by the analysis,
        # so a pair silent for that long holds nothing worth keeping.
        for key in [k for k, h in self._history.items()
                    if not h or now - h[-1] > self.max_interval_seconds]:
            del self._history[key]
            self._alerted.discard(key)

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")
        dst_port = meta.get("dst_port")
        if not (src_ip and dst_ip and dst_port is not None):
            return

        # Beacons are repeated *connections*; only count the first packet of
        # each flow, otherwise every packet of a bulk download looks periodic.
        if flow is not None and flow.packet_count > 1:
            return
        # A flow first seen through the server's packet: not this side's check-in.
        if flow is not None and flow.src_ip and flow.src_ip != src_ip:
            return
        # Service discovery / time sync / DNS are periodic by design.
        if _is_multicast_or_broadcast(dst_ip) or dst_port in _SYSTEM_SERVICE_PORTS:
            return
        # Command-and-control servers live on the internet.  Loopback helpers,
        # link-local housekeeping (DHCPv6, neighbour discovery) and LAN
        # devices (AirPlay receivers, printers, NAS) poll on timers by design.
        if classify_ip(dst_ip) != "public":
            return
        context = layer7.get("context") or {}
        # macOS's own daemons (trustd, transparencyd, configd …) check in with
        # Apple on fixed schedules.  They run from SIP-protected system paths
        # that malware cannot replace.
        if context.get("system_process"):
            return

        ts = meta.get("timestamp", time.time())
        key: Tuple[str, str, int] = (src_ip, dst_ip, dst_port)
        hist = self._history[key]
        hist.append(ts)

        if len(hist) < self.min_connections:
            return
        if key in self._alerted:
            return

        intervals = [
            hist[i] - hist[i - 1]
            for i in range(1, len(hist))
            if (hist[i] - hist[i - 1]) <= self.max_interval_seconds
        ]
        if len(intervals) < self.min_connections - 1:
            return

        mean = sum(intervals) / len(intervals)
        # Sub-second regularity is streaming/bulk traffic, not C2 check-ins.
        if mean < 1.0:
            return
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cv = stddev / mean

        if cv <= self.cv_threshold:
            self._alerted.add(key)
            app = context.get("app")
            host = context.get("remote_host")
            # A name taken from the client's own SNI / Host header, never
            # confirmed by a DNS answer for this IP, is whatever the program
            # chose to send — it must not make the alert quieter.
            verified = bool(host) and not context.get("remote_host_unverified")
            # Apps that poll a named server (mail sync, update checks, chat
            # presence) are the common benign case.  Malware more often calls
            # home to a bare IP it never looked up in DNS.
            severity = Severity.MEDIUM if verified else Severity.HIGH
            who = app or src_ip
            label = host if verified else (f"{host}?" if host else None)
            target = f"{label} ({dst_ip}:{dst_port})" if label else f"{dst_ip}:{dst_port}"
            suffix = ("" if verified else
                      " — name claimed by the client, not seen in DNS" if host else
                      " — bare IP with no DNS lookup")
            yield Alert(
                alert_type=AlertType.BEHAVIORAL,
                severity=severity,
                message=(
                    f"Regular check-ins: {who} contacted {target} every "
                    f"{_human_interval(mean)} like clockwork ({len(hist)} times, CV={cv:.2f})"
                    + suffix
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=meta.get("protocol"),
                mitre_technique="T1071",
                tags=["beaconing", "c2", "persistence"],
                confidence=max(0.0, 1.0 - cv / self.cv_threshold),
                evidence={
                    "mean_interval_seconds": round(mean, 2),
                    "stddev_seconds": round(stddev, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "sample_count": len(hist),
                    "hostname_known": verified,
                    "hostname_claimed": host if host and not verified else None,
                },
            )


def _human_interval(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"
