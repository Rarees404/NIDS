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
from typing import Any, Dict, Optional, Tuple


class HostnameCache:
    """
    Bounded LRU map of IP address → most recently observed hostname.

    Names from DNS answers are *verified*: the resolver said this IP serves
    that name.  An SNI or HTTP ``Host`` header is only what the client chose
    to send — malware can claim ``Host: google.com`` to any IP — so such a
    name counts as verified only when a DNS answer for the same (IP, name)
    pair was seen.  Unverified names are still remembered for display, but
    :meth:`is_verified` lets severity decisions and allowlists ignore them,
    and they never replace a verified name for the same IP.
    """

    def __init__(self, max_entries: int = 50_000) -> None:
        self._max = max_entries
        # ip -> (name, verified)
        self._names: "OrderedDict[str, Tuple[str, bool]]" = OrderedDict()
        # (ip, name) pairs seen in DNS answers (CDN IPs serve many names)
        self._dns_pairs: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        self._lock = threading.Lock()

    def learn(self, meta: Dict[str, Any], layer7: Dict[str, Any]) -> None:
        """Record any IP↔name association visible in this packet."""
        dns = layer7.get("dns")
        if dns and dns.get("answers"):
            query = dns.get("query_name")
            for answer in dns["answers"]:
                if answer.get("type") in ("A", "AAAA"):
                    ip = answer.get("data")
                    # Both the asked name and the CNAME target are vouched for.
                    for name in {query, answer.get("name")}:
                        self._vouch(ip, name)
                    # Prefer the name the user asked for over the CNAME target.
                    self.set(ip, query or answer.get("name"))
            return

        dst = meta.get("dst_ip")
        if not dst:
            return
        claimed = None
        tls = layer7.get("tls")
        quic = layer7.get("quic")
        http = layer7.get("http")
        if tls and tls.get("sni"):
            claimed = tls["sni"]
        elif quic and quic.get("sni"):
            claimed = quic["sni"]
        elif http and http.get("direction") == "request" and http.get("host"):
            claimed = http["host"].split(":")[0]
        if claimed:
            self.set(dst, claimed, verified=self._vouched(dst, claimed))

    def set(self, ip: str, name: Optional[str], verified: bool = True) -> None:
        if not ip or not name:
            return
        name = name.lower().rstrip(".")
        with self._lock:
            current = self._names.get(ip)
            if not verified and current is not None and current[1] and current[0] != name:
                return  # keep the DNS-backed name over a mere claim
            self._names.pop(ip, None)
            self._names[ip] = (name, verified)
            if len(self._names) > self._max:
                self._names.popitem(last=False)

    def lookup(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        with self._lock:
            entry = self._names.get(ip)
        return entry[0] if entry else None

    def is_verified(self, ip: Optional[str]) -> bool:
        """True when the name stored for *ip* is backed by a DNS answer."""
        if not ip:
            return False
        with self._lock:
            entry = self._names.get(ip)
        return bool(entry and entry[1])

    def _vouch(self, ip: Optional[str], name: Optional[str]) -> None:
        if not ip or not name:
            return
        key = (ip, name.lower().rstrip("."))
        with self._lock:
            self._dns_pairs.pop(key, None)
            self._dns_pairs[key] = None
            if len(self._dns_pairs) > self._max * 2:
                self._dns_pairs.popitem(last=False)

    def _vouched(self, ip: str, name: str) -> bool:
        with self._lock:
            return (ip, name.lower().rstrip(".")) in self._dns_pairs

    def __len__(self) -> int:
        return len(self._names)
