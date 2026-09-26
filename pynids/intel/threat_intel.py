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

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ThreatEntry:
    """A matched threat intelligence record."""

    category: str
    severity: str
    description: str
    indicator: str  # The CIDR or domain that matched


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
        self._domain_exact: Dict[str, ThreatEntry] = {}
        self._domain_suffix: Dict[str, ThreatEntry] = {}

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

    @property
    def ip_entry_count(self) -> int:
        return self._ip_count

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
        bucket = self._ip_index[network.version].setdefault(network.prefixlen, {})
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
            category=category, severity=severity,
            description=description, indicator=domain,
        )
        if domain.startswith("."):
            self._domain_suffix[domain.lstrip(".")] = entry
        else:
            self._domain_exact[domain] = entry

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
