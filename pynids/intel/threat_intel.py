"""
Threat intelligence integration for PyNIDS.

Loads local intelligence feeds (bad IPs and malicious domains) at startup
and exposes hash-based lookup methods used by the detection pipeline.

Feed formats
------------
bad_ips YAML::

    entries:
      - cidr: "185.220.101.0/24"
        category: tor_exit
        severity: MEDIUM
        description: "Known Tor exit relay range"
      - cidr: "198.51.100.1/32"
        category: c2
        severity: HIGH
        description: "Known C2 server"

malicious_domains YAML::

    entries:
      - domain: "malware-c2.example"
        category: c2
        severity: HIGH
        description: "Known C2 domain"
      - domain: ".onion.to"
        category: tor_proxy
        severity: MEDIUM
        description: "Tor proxy suffix"
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlsplit

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ThreatEntry:
    """A matched threat intelligence record."""

    category: str
    severity: str
    description: str
    indicator: str  # The CIDR, domain, URL or fingerprint that matched


class ThreatIntel:
    """
    In-memory threat intelligence store.

    Loads IP/CIDR and domain feeds from YAML files, plus any feeds cached by
    :mod:`pynids.intel.feeds`.  Both lookup methods run on every packet, so
    they are hash-based rather than linear:

    * IPs — one dict per (IP version, prefix length); a lookup masks the
      address once per distinct prefix length, most specific first.
    * Domains — exact and suffix dicts; a lookup walks the domain's label
      suffixes (``a.b.example.com`` → ``b.example.com`` → ``example.com`` …).

    Args:
        bad_ips_path:         Path to the bad IPs YAML feed.
        malicious_domains_path: Path to the malicious domains YAML feed.
    """

    def __init__(
        self,
        bad_ips_path: Optional[str] = None,
        malicious_domains_path: Optional[str] = None,
    ) -> None:
        # {ip_version: {prefix_len: {network_int: ThreatEntry}}}
        self._ip_index: Dict[int, Dict[int, Dict[int, ThreatEntry]]] = {4: {}, 6: {}}
        self._ip_count = 0
        # ip string → lookup result; flushed whenever the index changes.
        self._ip_cache: Dict[str, Optional[ThreatEntry]] = {}
        self._domain_exact: Dict[str, ThreatEntry] = {}
        self._domain_suffix: Dict[str, ThreatEntry] = {}
        # "host/path" → entry, for pages on hosts that are not bad as a whole
        self._urls: Dict[str, ThreatEntry] = {}
        # {"ja3": {md5: entry}, "cert_sha1": {sha1: entry}}
        self._fingerprints: Dict[str, Dict[str, ThreatEntry]] = {"ja3": {}, "cert_sha1": {}}

        if bad_ips_path:
            self._load_ips(bad_ips_path)
        if malicious_domains_path:
            self._load_domains(malicious_domains_path)

        logger.info(
            "ThreatIntel loaded: %d IP networks, %d domain patterns",
            self.ip_entry_count,
            self.domain_entry_count,
        )

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> Optional[ThreatEntry]:
        """
        Return the most specific matching threat entry for *ip*, or None.

        Supports both exact host matches and CIDR range lookups.
        """
        cache = self._ip_cache
        if ip in cache:
            return cache[ip]
        entry = self._check_ip_uncached(ip)
        if len(cache) >= 65536:
            cache.clear()
        cache[ip] = entry
        return entry

    def _check_ip_uncached(self, ip: str) -> Optional[ThreatEntry]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        by_prefix = self._ip_index[addr.version]
        if not by_prefix:
            return None
        value = int(addr)
        bits = addr.max_prefixlen
        for prefix in sorted(by_prefix, reverse=True):
            masked = (value >> (bits - prefix)) << (bits - prefix) if prefix else 0
            entry = by_prefix[prefix].get(masked)
            if entry is not None:
                return entry
        return None

    def check_domain(self, domain: str) -> Optional[ThreatEntry]:
        """
        Return the first matching threat entry for *domain*, or None.

        Domain matching supports both exact matches and suffix patterns
        (entries starting with a dot, e.g. ``.dyndns.org`` match any
        subdomain of that zone).
        """
        domain_lower = domain.lower().rstrip(".")
        if not domain_lower:
            return None
        entry = self._domain_exact.get(domain_lower)
        if entry is not None:
            return entry
        candidate = domain_lower
        while True:
            entry = self._domain_suffix.get(candidate)
            if entry is not None:
                return entry
            dot = candidate.find(".")
            if dot < 0:
                return None
            candidate = candidate[dot + 1:]

    def check_url(self, host: Optional[str], uri: Optional[str]) -> Optional[ThreatEntry]:
        """A listed page: *host* and request *uri* (query string optional)."""
        if not host or not self._urls:
            return None
        host = host.lower().rstrip(".")
        path = uri or "/"
        entry = self._urls.get(host + path)
        if entry is None and "?" in path:
            entry = self._urls.get(host + path.split("?", 1)[0])
        return entry

    def check_ja3(self, ja3: Optional[str]) -> Optional[ThreatEntry]:
        """A TLS client fingerprint (JA3 MD5) used by known malware."""
        return self._fingerprints["ja3"].get(ja3.lower()) if ja3 else None

    def check_cert(self, sha1: Optional[str]) -> Optional[ThreatEntry]:
        """A server certificate (SHA-1 of the DER bytes) used by known malware."""
        return self._fingerprints["cert_sha1"].get(sha1.lower()) if sha1 else None

    @property
    def ip_entry_count(self) -> int:
        return self._ip_count

    @property
    def url_entry_count(self) -> int:
        return len(self._urls)

    @property
    def fingerprint_entry_count(self) -> int:
        return sum(len(v) for v in self._fingerprints.values())

    @property
    def domain_entry_count(self) -> int:
        return len(self._domain_exact) + len(self._domain_suffix)

    # ------------------------------------------------------------------
    # Mutation (used by the YAML loaders and the feed cache)
    # ------------------------------------------------------------------

    def add_network(
        self, cidr: str, category: str, severity: str, description: str
    ) -> bool:
        """Index one IP or CIDR.  Returns False if *cidr* is invalid."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            logger.warning("ThreatIntel: invalid CIDR %r — %s", cidr, exc)
            return False
        severity = _normalise_severity(severity)
        bucket = self._ip_index[network.version].setdefault(network.prefixlen, {})
        self._ip_cache.clear()
        key = int(network.network_address)
        if key not in bucket:
            self._ip_count += 1
        bucket[key] = ThreatEntry(
            category=category, severity=severity,
            description=description, indicator=str(network),
        )
        return True

    def add_domain(
        self, domain: str, category: str, severity: str, description: str
    ) -> None:
        """Index a domain.  A leading dot makes it a suffix (zone) pattern."""
        domain = domain.lower().rstrip(".")
        if not domain:
            return
        entry = ThreatEntry(
            category=category, severity=_normalise_severity(severity),
            description=description, indicator=domain,
        )
        if domain.startswith("."):
            self._domain_suffix[domain.lstrip(".")] = entry
        else:
            self._domain_exact[domain] = entry

    def add_url(self, url: str, category: str, severity: str, description: str) -> bool:
        """
        Index a malicious page.

        A URL that is just a site root lists the whole host (so it is also
        caught by SNI and DNS); one with a path lists only that page, because
        the host may be a shared platform that is mostly legitimate.
        """
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return False
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return False
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        entry = ThreatEntry(category=category, severity=_normalise_severity(severity),
                            description=description, indicator=url.strip()[:300])
        if path == "/":
            try:
                ipaddress.ip_address(host)
                self.add_network(host, category, severity, description)
            except ValueError:
                self._domain_exact.setdefault(host, entry)
        self._urls[host + path] = entry
        return True

    def add_fingerprint(self, kind: str, value: str, category: str, severity: str,
                        description: str) -> None:
        """Index a ``ja3`` or ``cert_sha1`` fingerprint."""
        table = self._fingerprints.get(kind)
        value = (value or "").strip().lower()
        if table is None or not value:
            return
        table[value] = ThreatEntry(category=category, severity=_normalise_severity(severity),
                                   description=description, indicator=value)

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def _load_ips(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning("ThreatIntel: bad_ips file not found: %s", path)
            return
        try:
            with p.open(encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for item in data.get("entries", []):
                self.add_network(
                    item.get("cidr", ""),
                    item.get("category", "unknown"),
                    item.get("severity", "MEDIUM"),
                    item.get("description", ""),
                )
        except Exception as exc:
            logger.error("ThreatIntel: failed to load %s — %s", path, exc)

    def _load_domains(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning("ThreatIntel: malicious_domains file not found: %s", path)
            return
        try:
            with p.open(encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for item in data.get("entries", []):
                self.add_domain(
                    item.get("domain", ""),
                    item.get("category", "unknown"),
                    item.get("severity", "MEDIUM"),
                    item.get("description", ""),
                )
        except Exception as exc:
            logger.error("ThreatIntel: failed to load %s — %s", path, exc)


_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _normalise_severity(value: object) -> str:
    """``"high"`` → ``"HIGH"``; anything unrecognised becomes ``"MEDIUM"``."""
    sev = str(value or "").strip().upper()
    if sev not in _SEVERITIES:
        logger.warning("ThreatIntel: unknown severity %r, using MEDIUM", value)
        return "MEDIUM"
    return sev
