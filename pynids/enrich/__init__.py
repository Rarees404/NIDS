"""
Context enrichment: who (app/process), where (hostname, country, ASN).

The :class:`Enricher` runs once per packet inside the engine and returns a
small ``context`` dict.  The engine attaches it to every alert raised by
that packet and hands it to packet observers (the live traffic stats that
power the dashboard's per-app and world-map views).
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .geo import GeoResolver
from .hostnames import HostnameCache
from .process import ProcessResolver, is_system_daemon, local_addresses

__all__ = ["Enricher", "GeoResolver", "HostnameCache", "ProcessResolver"]


def _is_loopback(ip: Optional[str]) -> bool:
    return bool(ip) and (ip.startswith("127.") or ip == "::1")


class Enricher:
    """
    Combine process attribution, passive hostname learning, and GeoIP.

    Every component is optional; missing ones simply leave their keys out
    of the context.
    """

    def __init__(
        self,
        processes: Optional[ProcessResolver] = None,
        geo: Optional[GeoResolver] = None,
        hostnames: Optional[HostnameCache] = None,
        local_ips: Optional[frozenset] = None,
        signatures: Any = None,
    ) -> None:
        self.processes = processes
        # Optional SignatureChecker; lookups never block (unknown → checked in background).
        self.signatures = signatures if signatures is not None and signatures.available else None
        self.geo = geo if geo is not None and geo.available else None
        self.hostnames = hostnames or HostnameCache()
        self._fixed_local = local_ips
        self._local_ips = local_ips or local_addresses()
        self._local_refreshed = time.monotonic()

    @property
    def local_ips(self) -> frozenset:
        # Interfaces come and go (Wi-Fi roaming, VPNs) — refresh every 30 s.
        if self._fixed_local is None and time.monotonic() - self._local_refreshed > 30:
            self._local_ips = local_addresses()
            self._local_refreshed = time.monotonic()
        return self._local_ips

    def packet_context(self, meta: Dict[str, Any], layer7: Dict[str, Any]) -> Dict[str, Any]:
        self.hostnames.learn(meta, layer7)

        src, dst = meta.get("src_ip"), meta.get("dst_ip")
        if not src or not dst:
            return {}
        local = self.local_ips
        src_local = src in local or _is_loopback(src)
        dst_local = dst in local or _is_loopback(dst)
        if src_local and not dst_local:
            direction, remote = "outbound", dst
        elif dst_local and not src_local:
            direction, remote = "inbound", src
        elif src_local and dst_local:
            direction, remote = "local", dst
        else:
            direction, remote = "transit", dst

        ctx: Dict[str, Any] = {"direction": direction, "remote_ip": remote}

        if self.processes is not None:
            proc = self.processes.lookup_packet(meta, local)
            if proc:
                ctx["app"] = proc["app"]
                ctx["process"] = proc["process"]
                ctx["pid"] = proc["pid"]
                exe = proc.get("exe")
                if exe:
                    ctx["exe"] = exe
                if is_system_daemon(exe):
                    ctx["system_process"] = True
                elif exe and self.signatures is not None:
                    sig = self.signatures.lookup(exe)
                    if sig:
                        ctx["signature"] = sig.get("status")
            if direction == "local":
                # Which program owns the port being connected to.
                target = self.processes.lookup(meta.get("protocol"), meta.get("dst_port"))
                if target and target is not proc:
                    ctx["target_app"] = target["app"]

        host = self.hostnames.lookup(remote)
        if host:
            ctx["remote_host"] = host

        if self.geo is not None and direction in ("outbound", "inbound", "transit"):
            geo = self.geo.lookup(remote)
            if geo:
                ctx.update(geo)
        return ctx
