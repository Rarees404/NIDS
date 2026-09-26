"""
IP → hostname memory, learned passively from the traffic itself.

Every DNS answer, TLS/QUIC SNI, and HTTP Host header tells us which name
the machine associated with an IP moments before connecting to it.  This
is far more accurate than reverse DNS (which returns CDN node names such
as ``lhr25s34-in-f14.1e100.net``) and costs nothing.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, Optional


class HostnameCache:
    """Bounded LRU map of IP address → most recently observed hostname."""

    def __init__(self, max_entries: int = 50_000) -> None:
        self._max = max_entries
        self._names: "OrderedDict[str, str]" = OrderedDict()
        self._lock = threading.Lock()

    def learn(self, meta: Dict[str, Any], layer7: Dict[str, Any]) -> None:
        """Record any IP↔name association visible in this packet."""
        dns = layer7.get("dns")
        if dns and dns.get("answers"):
            query = dns.get("query_name")
            for answer in dns["answers"]:
                if answer.get("type") in ("A", "AAAA"):
                    # Prefer the name the user asked for over the CNAME target.
                    self.set(answer["data"], query or answer.get("name"))
            return

        dst = meta.get("dst_ip")
        if not dst:
            return
        tls = layer7.get("tls")
        if tls and tls.get("sni"):
            self.set(dst, tls["sni"])
            return
        quic = layer7.get("quic")
        if quic and quic.get("sni"):
            self.set(dst, quic["sni"])
            return
        http = layer7.get("http")
        if http and http.get("direction") == "request" and http.get("host"):
            self.set(dst, http["host"].split(":")[0])

    def set(self, ip: str, name: Optional[str]) -> None:
        if not ip or not name:
            return
        name = name.lower().rstrip(".")
        with self._lock:
            self._names.pop(ip, None)
            self._names[ip] = name
            if len(self._names) > self._max:
                self._names.popitem(last=False)

    def lookup(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        with self._lock:
            return self._names.get(ip)

    def __len__(self) -> int:
        return len(self._names)
