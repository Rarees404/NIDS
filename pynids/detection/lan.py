"""
Local-network (layer 2 / link) detectors.

Everything above watches IP conversations.  The attacks that put someone
*between* this machine and its router happen one layer down, in frames the
IP detectors never see:

:class:`ArpSpoofDetector`
    The router's IP address suddenly answering from a different MAC
    (``LAN-ARP-GATEWAY``), two devices fighting over one address
    (``LAN-ARP-CONFLICT``), one device answering for many addresses
    (``LAN-ARP-MULTI``), and one device asking for every address on the
    subnet (``LAN-ARP-SWEEP``).  MITRE: T1557.002 / T1018.

:class:`PingSweepDetector`
    One source pinging many hosts — host discovery without ports, which the
    port-scan detector cannot count.  MITRE: T1018.

:class:`RogueServiceDetector`
    A second DHCP server (``LAN-DHCP-ROGUE``) or a second IPv6 router
    (``LAN-RA-ROUTER``) answering on the network: whoever wins hands out the
    default gateway and DNS server, i.e. decides where traffic goes.
    MITRE: T1557.003.

All state is learned from the traffic itself.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow

logger = logging.getLogger(__name__)

_ZERO_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def default_gateways(timeout: float = 2.0) -> Set[str]:
    """IPv4 default-gateway addresses from the routing table (empty if unknown)."""
    commands = (["route", "-n", "get", "default"], ["ip", "-4", "route", "show", "default"])
    found: Set[str] = set()
    for cmd in commands:
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        found.update(re.findall(r"(?:gateway:|default via)\s+(\d{1,3}(?:\.\d{1,3}){3})", out))
        if found:
            break
    return found


class _Cooldown:
    """Remember when something last alerted; bounded."""

    def __init__(self, seconds: float, cap: int = 5000) -> None:
        self.seconds = seconds
        self._cap = cap
        self._last: Dict[Any, float] = {}

    def ready(self, key: Any, now: float) -> bool:
        last = self._last.get(key)
        if last is not None and now - last < self.seconds:
            return False
        if len(self._last) >= self._cap:
            self._last.clear()
        self._last[key] = now
        return True

    def prune(self, now: float) -> None:
        self._last = {k: t for k, t in self._last.items() if now - t < self.seconds}


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------

class ArpSpoofDetector(BaseDetector):
    """
    Watch which MAC address answers for which IP address.

    Args:
        gateways:        Callable returning the default-gateway IPs (looked up
                         at most once a minute, and only when a binding changes).
        conflict_window: Seconds within which an address must change hands
                         twice to count as two devices fighting over it.
        claim_threshold: Distinct IPs one MAC may answer for within
                         ``claim_window`` seconds.
        sweep_threshold: Distinct IPs one MAC may ask for within ``sweep_window``.
        forget_after:    A binding not seen for this long is relearned silently
                         (a lease that moved to another device).
    """

    def __init__(
        self,
        gateways: Optional[Callable[[], Iterable[str]]] = default_gateways,
        conflict_window: float = 300.0,
        claim_threshold: int = 5,
        claim_window: float = 60.0,
        sweep_threshold: int = 50,
        sweep_window: float = 60.0,
        forget_after: float = 1800.0,
        cooldown: float = 600.0,
    ) -> None:
        self._gateway_source = gateways
        self.conflict_window = conflict_window
        self.claim_threshold = claim_threshold
        self.claim_window = claim_window
        self.sweep_threshold = sweep_threshold
        self.sweep_window = sweep_window
        self.forget_after = forget_after
        # ip -> [mac, last seen]
        self._bindings: Dict[str, List[Any]] = {}
        # ip -> times its MAC changed
        self._changes: Dict[str, Deque[float]] = {}
        # mac -> {ip: last claimed} (replies) / {ip: last asked for} (requests)
        self._claims: Dict[str, Dict[str, float]] = {}
        self._asked: Dict[str, Dict[str, float]] = {}
        self._gateways: Set[str] = set()       # from the routing table
        self._dhcp_routers: Set[str] = set()   # from DHCP answers seen on the wire
        self._gateways_checked = -1e18
        self._cooldown = _Cooldown(cooldown)

    @property
    def name(self) -> str:
        return "lan_arp"

    def prune(self, now: float) -> None:
        for ip in [i for i, b in self._bindings.items() if now - b[1] > self.forget_after]:
            del self._bindings[ip]
        for table, window in ((self._claims, self.claim_window), (self._asked, self.sweep_window)):
            for mac in list(table):
                live = {ip: t for ip, t in table[mac].items() if now - t <= window}
                if live:
                    table[mac] = live
                else:
                    del table[mac]
        for ip in [i for i, d in self._changes.items() if not d or now - d[-1] > self.conflict_window]:
            del self._changes[ip]
        self._cooldown.prune(now)

    def _is_gateway(self, ip: str, now: float) -> bool:
        if ip in self._dhcp_routers:
            return True
        if self._gateway_source is not None and now - self._gateways_checked > 60.0:
            self._gateways_checked = now
            try:
                self._gateways = set(self._gateway_source())
            except Exception as exc:  # noqa: BLE001
                logger.debug("gateway lookup failed: %s", exc)
        return ip in self._gateways

    def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
        dhcp = layer7.get("dhcp")
        if dhcp and dhcp.get("msg_type") == "ACK":
            # A fresh lease: possibly a different network that reuses the same
            # addresses.  What was learned before no longer applies.
            self._bindings.clear()
            self._changes.clear()
            self._dhcp_routers = set(dhcp.get("routers") or ())
            return
        arp = meta.get("arp")
        if not arp:
            return
        mac, ip = arp.get("sender_mac"), arp.get("sender_ip")
        if not mac or not ip or ip == "0.0.0.0" or mac in (_ZERO_MAC, _BROADCAST_MAC):
            return  # an address probe, not a claim
        now = meta.get("timestamp") or time.time()

        yield from self._check_binding(ip, mac, now)
        if arp.get("op") == "reply":
            yield from self._check_claims(ip, mac, now)
        elif arp.get("op") == "request" and arp.get("target_ip") != ip:
            yield from self._check_sweep(ip, mac, arp.get("target_ip"), now)

    # -- who owns this address ----------------------------------------------

    def _check_binding(self, ip: str, mac: str, now: float) -> Iterable[Alert]:
        binding = self._bindings.get(ip)
        if binding is None or now - binding[1] > self.forget_after:
            if binding is None and len(self._bindings) >= 20_000:
                self._bindings.clear()
            self._bindings[ip] = [mac, now]
            return
        old = binding[0]
        binding[1] = now
        if old == mac:
            return
        binding[0] = mac

        if self._is_gateway(ip, now):
            if self._cooldown.ready(("gw", ip), now):
                yield Alert(
                    alert_type=AlertType.ANOMALY,
                    severity=Severity.HIGH,
                    message=(f"Your router's address {ip} moved from {old} to {mac} — another device "
                             f"may be placing itself between you and the internet (ARP spoofing)"),
                    src_ip=ip,
                    protocol="arp",
                    rule_id="LAN-ARP-GATEWAY",
                    mitre_technique="T1557.002",
                    tags=["arp_spoof", "mitm", "lan"],
                    confidence=0.8,
                    evidence={"ip": ip, "previous_mac": old, "new_mac": mac, "role": "default gateway"},
                )
            return

        changes = self._changes.setdefault(ip, deque(maxlen=16))
        while changes and now - changes[0] > self.conflict_window:
            changes.popleft()
        changes.append(now)
        # One change is a lease moving to another device.  Back and forth
        # means two devices are answering for the address at the same time.
        if len(changes) >= 2 and self._cooldown.ready(("conflict", ip), now):
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.MEDIUM,
                message=(f"Two devices claim the address {ip} ({old} and {mac}) — an address "
                         f"conflict, or one of them is impersonating the other"),
                src_ip=ip,
                protocol="arp",
                rule_id="LAN-ARP-CONFLICT",
                mitre_technique="T1557.002",
                tags=["arp_spoof", "mitm", "lan", "address_conflict"],
                confidence=0.6,
                evidence={"ip": ip, "macs": sorted({old, mac}), "changes": len(changes),
                          "window_seconds": self.conflict_window},
            )

    # -- one device, many addresses -----------------------------------------

    def _check_claims(self, ip: str, mac: str, now: float) -> Iterable[Alert]:
        claims = self._claims.setdefault(mac, {})
        claims[ip] = now
        if len(claims) < self.claim_threshold:
            return
        for old_ip in [i for i, t in claims.items() if now - t > self.claim_window]:
            del claims[old_ip]
        if len(claims) >= self.claim_threshold and self._cooldown.ready(("multi", mac), now):
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(f"One device ({mac}) is answering for {len(claims)} different addresses on your "
                         f"network — the pattern of an ARP-spoofing tool redirecting everyone's traffic"),
                src_ip=ip,
                protocol="arp",
                rule_id="LAN-ARP-MULTI",
                mitre_technique="T1557.002",
                tags=["arp_spoof", "mitm", "lan"],
                confidence=0.7,
                evidence={"mac": mac, "claimed_ips": sorted(claims)[:40], "count": len(claims),
                          "window_seconds": self.claim_window},
            )

    def _check_sweep(self, ip: str, mac: str, target: Optional[str], now: float) -> Iterable[Alert]:
        if not target:
            return
        asked = self._asked.setdefault(mac, {})
        asked[target] = now
        if len(asked) < self.sweep_threshold:
            return
        for old_ip in [i for i, t in asked.items() if now - t > self.sweep_window]:
            del asked[old_ip]
        if len(asked) >= self.sweep_threshold and self._cooldown.ready(("sweep", mac), now):
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.LOW,
                message=(f"{ip} ({mac}) asked for {len(asked)} addresses in {self.sweep_window:.0f}s — "
                         f"it is mapping which devices are on your network"),
                src_ip=ip,
                protocol="arp",
                rule_id="LAN-ARP-SWEEP",
                mitre_technique="T1018",
                tags=["recon", "arp_sweep", "lan"],
                confidence=0.5,
                evidence={"mac": mac, "addresses_asked": len(asked), "window_seconds": self.sweep_window,
                          "sample_targets": sorted(asked)[:10]},
            )


# ---------------------------------------------------------------------------
# Ping sweeps
# ---------------------------------------------------------------------------

class PingSweepDetector(BaseDetector):
    """One source sending echo requests to many different hosts."""

    def __init__(self, threshold: int = 20, window: float = 60.0) -> None:
        self.threshold = threshold
        self.window = window
        # src -> {dst: last ping}
        self._targets: Dict[str, Dict[str, float]] = {}
        self._cooldown = _Cooldown(window)

    @property
    def name(self) -> str:
        return "ping_sweep"

    def prune(self, now: float) -> None:
        for src in list(self._targets):
            live = {d: t for d, t in self._targets[src].items() if now - t <= self.window}
            if live:
                self._targets[src] = live
            else:
                del self._targets[src]
        self._cooldown.prune(now)

    def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
        proto, kind = meta.get("protocol"), meta.get("icmp_type")
        if not ((proto == "icmp" and kind == 8) or (proto == "icmpv6" and kind == 128)):
            return
        src, dst = meta.get("src_ip"), meta.get("dst_ip")
        if not src or not dst or dst.endswith(".255") or dst.lower().startswith("ff"):
            return  # broadcast / multicast ping is one packet, not a sweep
        now = meta.get("timestamp") or time.time()
        targets = self._targets.setdefault(src, {})
        if dst not in targets and len(targets) >= 4096:
            return
        targets[dst] = now
        if len(targets) < self.threshold:
            return
        for old in [d for d, t in targets.items() if now - t > self.window]:
            del targets[old]
        if len(targets) >= self.threshold and self._cooldown.ready(src, now):
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.MEDIUM,
                message=f"Ping sweep from {src}: {len(targets)} hosts pinged in {self.window:.0f}s",
                src_ip=src,
                protocol=proto,
                mitre_technique="T1018",
                tags=["recon", "host_sweep", "ping_sweep"],
                confidence=min(1.0, len(targets) / (self.threshold * 2)),
                evidence={"hosts_pinged": len(targets), "window_seconds": self.window,
                          "sample_targets": sorted(targets)[:10]},
            )


# ---------------------------------------------------------------------------
# Rogue DHCP servers and IPv6 routers
# ---------------------------------------------------------------------------

class RogueServiceDetector(BaseDetector):
    """
    Two different DHCP servers, or two different IPv6 routers, answering
    within ``window`` seconds of each other.

    A network normally has one of each.  Moving to another network also
    shows a "new" server, but the old one is then silent — so only servers
    that are active at the same time count.
    """

    def __init__(self, window: float = 600.0, cooldown: float = 86400.0) -> None:
        self.window = window
        # server id -> (last seen, what it handed out)
        self._dhcp: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._routers: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._cooldown = _Cooldown(cooldown)

    @property
    def name(self) -> str:
        return "lan_rogue_service"

    def prune(self, now: float) -> None:
        for table in (self._dhcp, self._routers):
            for key in [k for k, v in table.items() if now - v[0] > self.window]:
                del table[key]
        self._cooldown.prune(now)

    def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
        now = meta.get("timestamp") or time.time()
        dhcp = layer7.get("dhcp")
        if dhcp and dhcp.get("op") == "reply" and dhcp.get("msg_type") in ("OFFER", "ACK"):
            server = dhcp.get("server_id") or meta.get("src_ip")
            if server:
                offer = {"server": server, "mac": meta.get("src_mac"), "routers": dhcp.get("routers"),
                         "dns_servers": dhcp.get("dns_servers")}
                yield from self._seen(self._dhcp, server, offer, now, meta, dhcp=True)
            return
        if meta.get("icmp_type") == 134 and meta.get("ra_lifetime") and meta.get("src_ip", "").startswith("fe80"):
            router = meta.get("src_mac") or meta["src_ip"]
            info = {"router": meta["src_ip"], "mac": meta.get("src_mac"), "lifetime": meta.get("ra_lifetime")}
            yield from self._seen(self._routers, router, info, now, meta, dhcp=False)

    def _seen(self, table: Dict[str, Tuple[float, Dict[str, Any]]], key: str, info: Dict[str, Any],
              now: float, meta: dict, dhcp: bool) -> Iterable[Alert]:
        others = [(k, v[1]) for k, v in table.items() if k != key and now - v[0] <= self.window]
        if len(table) >= 256 and key not in table:
            table.clear()
        table[key] = (now, info)
        if not others:
            return
        pair = tuple(sorted([key] + [k for k, _ in others]))
        if not self._cooldown.ready(("dhcp" if dhcp else "ra", pair), now):
            return
        if dhcp:
            names = ", ".join(sorted(str(k) for k in pair))
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.HIGH,
                message=(f"More than one DHCP server is answering on your network ({names}) — a rogue "
                         f"server can hand out its own router and DNS addresses to intercept traffic"),
                src_ip=meta.get("src_ip"),
                dst_ip=meta.get("dst_ip"),
                protocol="udp",
                rule_id="LAN-DHCP-ROGUE",
                mitre_technique="T1557.003",
                tags=["rogue_dhcp", "mitm", "lan"],
                confidence=0.7,
                evidence={"servers": [info] + [o for _, o in others], "window_seconds": self.window},
            )
        else:
            yield Alert(
                alert_type=AlertType.ANOMALY,
                severity=Severity.MEDIUM,
                message=(f"A second IPv6 router ({info['router']}, {info.get('mac') or 'unknown MAC'}) is "
                         f"advertising itself on your network — IPv6 traffic can be diverted through it"),
                src_ip=meta.get("src_ip"),
                protocol="icmpv6",
                rule_id="LAN-RA-ROUTER",
                mitre_technique="T1557",
                tags=["rogue_ra", "mitm", "lan"],
                confidence=0.5,
                evidence={"routers": [info] + [o for _, o in others], "window_seconds": self.window},
            )
