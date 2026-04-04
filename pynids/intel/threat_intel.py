"""
Threat intelligence integration for PyNIDS.

Loads local intelligence feeds (bad IPs and malicious domains) at startup
and exposes fast O(1) / O(n) lookup methods used by the detection pipeline.

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
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

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

    Loads IP/CIDR and domain feeds from YAML files.  Both lookup methods
    are designed to be called on every packet (kept as fast as possible).

    Args:
        bad_ips_path:         Path to the bad IPs YAML feed.
        malicious_domains_path: Path to the malicious domains YAML feed.
    """

    def __init__(
        self,
        bad_ips_path: Optional[str] = None,
        malicious_domains_path: Optional[str] = None,
    ) -> None:
        self._ip_entries: List[Dict[str, Any]] = []  # [{network, category, severity, desc}]
        self._domain_entries: List[Dict[str, Any]] = []  # [{pattern, is_suffix, category, …}]

        if bad_ips_path:
            self._load_ips(bad_ips_path)
        if malicious_domains_path:
            self._load_domains(malicious_domains_path)

        logger.info(
            "ThreatIntel loaded: %d IP networks, %d domain patterns",
            len(self._ip_entries),
            len(self._domain_entries),
        )

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def check_ip(self, ip: str) -> Optional[ThreatEntry]:
        """
        Return the first matching threat entry for *ip*, or None.

        Supports both exact host matches and CIDR range lookups.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        for entry in self._ip_entries:
            if addr in entry["network"]:
                return ThreatEntry(
                    category=entry["category"],
                    severity=entry["severity"],
                    description=entry["description"],
                    indicator=str(entry["network"]),
                )
        return None

    def check_domain(self, domain: str) -> Optional[ThreatEntry]:
        """
        Return the first matching threat entry for *domain*, or None.

        Domain matching supports both exact matches and suffix patterns
        (entries starting with a dot, e.g. ``.dyndns.org`` match any
        subdomain of that zone).
        """
        domain_lower = domain.lower().rstrip(".")
        for entry in self._domain_entries:
            pattern: str = entry["pattern"]
            if entry["is_suffix"]:
                if domain_lower == pattern.lstrip(".") or domain_lower.endswith(pattern):
                    return ThreatEntry(
                        category=entry["category"],
                        severity=entry["severity"],
                        description=entry["description"],
                        indicator=pattern,
                    )
            else:
                if domain_lower == pattern:
                    return ThreatEntry(
                        category=entry["category"],
                        severity=entry["severity"],
                        description=entry["description"],
                        indicator=pattern,
                    )
        return None

    @property
    def ip_entry_count(self) -> int:
        return len(self._ip_entries)

    @property
    def domain_entry_count(self) -> int:
        return len(self._domain_entries)

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
                cidr = item.get("cidr", "")
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    self._ip_entries.append(
                        {
                            "network": network,
                            "category": item.get("category", "unknown"),
                            "severity": item.get("severity", "MEDIUM"),
                            "description": item.get("description", ""),
                        }
                    )
                except ValueError as exc:
                    logger.warning("ThreatIntel: invalid CIDR %r — %s", cidr, exc)
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
                domain = item.get("domain", "").lower().rstrip(".")
                if not domain:
                    continue
                self._domain_entries.append(
                    {
                        "pattern": domain,
                        "is_suffix": domain.startswith("."),
                        "category": item.get("category", "unknown"),
                        "severity": item.get("severity", "MEDIUM"),
                        "description": item.get("description", ""),
                    }
                )
        except Exception as exc:
            logger.error("ThreatIntel: failed to load %s — %s", path, exc)
