"""
Live threat-intelligence and privacy feeds.

This module pulls real, free, keyless feeds, normalises them, and caches
them as JSON in the data directory so the engine can load them at startup
without network access.  The daemon refreshes them every few hours.

Feeds
-----
=================  ================================================  ==============
name               source                                            used for
=================  ================================================  ==============
feodo              abuse.ch Feodo Tracker botnet C2 IPs              threat IP
c2intel_ips        C2IntelFeeds: C2 servers seen in the last 30 d    threat IP
c2intel_domains    C2IntelFeeds: C2 domains seen in the last 30 d    threat domain
spamhaus_drop_v4   Spamhaus DROP (hijacked / criminal netblocks)     threat IP
spamhaus_drop_v6   Spamhaus DROP IPv6                                threat IP
et_compromised     Emerging Threats compromised hosts                threat IP
blocklist_de       blocklist.de hosts reported for attacks           threat IP
tor_relays         Tor Project Onionoo: every running relay          threat IP
tor_exits          Tor Project bulk exit list                        threat IP
openphish          OpenPhish community phishing URLs                 threat URL/host
sslbl_certs        abuse.ch SSLBL malicious certificate SHA-1s       TLS certificate
sslbl_ja3          abuse.ch SSLBL malware JA3 client fingerprints    TLS fingerprint
disconnect         Disconnect.me tracker list (ads, analytics, …)    trackers
doh_domains        dibdot DoH resolver hostnames                     DoH detector
doh_ipv4           dibdot DoH resolver IPv4 addresses                DoH detector
=================  ================================================  ==============

abuse.ch's URLhaus and ThreatFox bulk downloads now answer ``410 Gone``
without an account key, so they are no longer fetched here; both remain
available as keyed lookups in the SOC workbench.

Relays versus exits: an *exit* address is where Tor traffic comes out, so
it matters for inbound connections.  A connection from this machine *to*
any relay means a Tor client is running here.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .. import __version__
from ..paths import intel_dir
from .threat_intel import ThreatIntel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parsers — each turns raw feed text into the cached "entries" value
# ---------------------------------------------------------------------------

def _parse_ip_lines(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.split()[0])
    return out


def _parse_spamhaus_json(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if "cidr" in obj:
            out.append(obj["cidr"])
    return out


def _parse_hostfile(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2 and parts[1] not in ("localhost",):
            out.append(parts[1].lower())
    return out


def _parse_domain_lines(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line and " " not in line:
            out.append(line)
    return out


def _parse_csv_first(text: str) -> List[str]:
    """First column of a CSV, skipping comment / header lines."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value = line.split(",", 1)[0].strip().strip('"').lower()
        if value:
            out.append(value)
    return out


def _parse_url_lines(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(("http://", "https://")) and " " not in line:
            out.append(line)
    return out


def _parse_sslbl(column: int, length: int) -> Callable[[str], Dict[str, str]]:
    """abuse.ch SSLBL CSV → ``{hex fingerprint: listing reason}``."""
    def parse(text: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            cols = [c.strip() for c in line.split(",")]
            if len(cols) <= column:
                continue
            value = cols[column].lower()
            if len(value) == length and all(c in "0123456789abcdef" for c in value):
                out[value] = cols[-1] or "listed"
        return out
    return parse


def _parse_onionoo(text: str) -> List[str]:
    """Onionoo ``details`` document → every relay's OR addresses, without ports."""
    out: List[str] = []
    seen: Set[str] = set()
    for relay in json.loads(text).get("relays") or []:
        for address in relay.get("or_addresses") or []:
            host = address.rsplit(":", 1)[0].strip("[]")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
    return out


# Disconnect categories worth surfacing.  "Content" (YouTube embeds, CDNs)
# and the internal "Disconnect" category are too noisy to flag.
_DISCONNECT_CATEGORIES = {
    "Advertising", "Analytics", "Social", "Cryptomining",
    "FingerprintingInvasive", "FingerprintingGeneral", "Email", "EmailAggressive",
}


def _parse_disconnect(text: str) -> Dict[str, str]:
    data = json.loads(text)
    out: Dict[str, str] = {}
    for category, companies in (data.get("categories") or {}).items():
        if category not in _DISCONNECT_CATEGORIES:
            continue
        for company_obj in companies:
            for company, sites in company_obj.items():
                if not isinstance(sites, dict):
                    continue
                for value in sites.values():
                    if not isinstance(value, list):
                        continue
                    for domain in value:
                        if isinstance(domain, str) and domain:
                            out.setdefault(domain.lower(), f"{company} ({category})")
    return out


# ---------------------------------------------------------------------------
# Feed registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FeedSpec:
    name: str
    url: str
    kind: str  # "ip" | "domain" | "url" | "cert_sha1" | "ja3" | "trackers" | "doh_domain" | "doh_ip"
    description: str
    category: str
    severity: str
    parser: Callable[[str], Any]


FEEDS: Tuple[FeedSpec, ...] = (
    FeedSpec("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
             "ip", "Feodo Tracker botnet C2 server", "c2", "CRITICAL", _parse_ip_lines),
    FeedSpec("c2intel_ips",
             "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
             "ip", "C2IntelFeeds — command-and-control server seen in the last 30 days", "c2", "HIGH",
             _parse_csv_first),
    FeedSpec("c2intel_domains",
             "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
             "domain", "C2IntelFeeds — command-and-control domain seen in the last 30 days", "c2", "HIGH",
             _parse_csv_first),
    FeedSpec("spamhaus_drop_v4", "https://www.spamhaus.org/drop/drop_v4.json",
             "ip", "Spamhaus DROP — hijacked or criminal netblock", "drop", "HIGH",
             _parse_spamhaus_json),
    FeedSpec("spamhaus_drop_v6", "https://www.spamhaus.org/drop/drop_v6.json",
             "ip", "Spamhaus DROP — hijacked or criminal netblock", "drop", "HIGH",
             _parse_spamhaus_json),
    FeedSpec("et_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
             "ip", "Emerging Threats — compromised host used for attacks", "compromised", "MEDIUM",
             _parse_ip_lines),
    FeedSpec("blocklist_de", "https://lists.blocklist.de/lists/all.txt",
             "ip", "blocklist.de — reported for attacking servers in the last 48 hours", "attacker", "LOW",
             _parse_ip_lines),
    # Relays first: an address that is also an exit keeps the exit label.
    FeedSpec("tor_relays",
             "https://onionoo.torproject.org/details?type=relay&running=true&fields=or_addresses",
             "ip", "Tor relay — a connection to it means Tor is in use", "tor_relay", "LOW",
             _parse_onionoo),
    FeedSpec("tor_exits", "https://check.torproject.org/torbulkexitlist",
             "ip", "Tor exit relay", "tor_exit", "LOW", _parse_ip_lines),
    FeedSpec("openphish",
             "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
             "url", "OpenPhish — reported phishing page", "phishing", "HIGH", _parse_url_lines),
    FeedSpec("sslbl_certs", "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
             "cert_sha1", "abuse.ch SSLBL — certificate used by malware", "malware", "HIGH",
             _parse_sslbl(column=1, length=40)),
    FeedSpec("sslbl_ja3", "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
             "ja3", "abuse.ch SSLBL — TLS client fingerprint of malware", "malware", "MEDIUM",
             _parse_sslbl(column=0, length=32)),
    FeedSpec("disconnect",
             "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json",
             "trackers", "Disconnect.me tracker list", "tracker", "LOW", _parse_disconnect),
    FeedSpec("doh_domains",
             "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt",
             "doh_domain", "DNS-over-HTTPS resolver", "doh", "MEDIUM", _parse_domain_lines),
    FeedSpec("doh_ipv4",
             "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt",
             "doh_ip", "DNS-over-HTTPS resolver", "doh", "MEDIUM", _parse_ip_lines),
)

FEEDS_BY_NAME = {f.name: f for f in FEEDS}


# ---------------------------------------------------------------------------
# Download + cache
# ---------------------------------------------------------------------------

@dataclass
class FeedResult:
    name: str
    ok: bool
    entries: int = 0
    error: Optional[str] = None


def _fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"PyNIDS/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https URLs
        return resp.read().decode("utf-8", errors="replace")


def update_feeds(
    directory: Optional[Path] = None,
    names: Optional[Iterable[str]] = None,
    timeout: float = 30.0,
    fetch: Callable[[str, float], str] = _fetch,
) -> List[FeedResult]:
    """Download the selected feeds (all by default) into the cache directory."""
    directory = Path(directory) if directory else intel_dir()
    directory.mkdir(parents=True, exist_ok=True)
    selected = [FEEDS_BY_NAME[n] for n in names] if names else list(FEEDS)
    results: List[FeedResult] = []
    for spec in selected:
        try:
            entries = spec.parser(fetch(spec.url, timeout))
            if not entries:
                raise ValueError("feed returned no entries")
            payload = {"name": spec.name, "url": spec.url, "fetched": time.time(),
                       "entries": entries}
            tmp = directory / f"{spec.name}.json.tmp"
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(directory / f"{spec.name}.json")
            results.append(FeedResult(spec.name, True, len(entries)))
            logger.info("Feed %s updated: %d entries", spec.name, len(entries))
        except Exception as exc:  # noqa: BLE001 — one bad feed must not stop the rest
            results.append(FeedResult(spec.name, False, error=str(exc)))
            logger.warning("Feed %s failed: %s", spec.name, exc)
    return results


def _read_cache(directory: Path, name: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def feed_status(directory: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return one row per feed: name, description, entry count, fetch time."""
    directory = Path(directory) if directory else intel_dir()
    rows = []
    for spec in FEEDS:
        cached = _read_cache(directory, spec.name)
        rows.append({
            "name": spec.name,
            "kind": spec.kind,
            "description": spec.description,
            "entries": len(cached["entries"]) if cached else 0,
            "fetched": cached.get("fetched") if cached else None,
        })
    return rows


def oldest_fetch_age(directory: Optional[Path] = None) -> float:
    """Seconds since the stalest feed was fetched (inf if any are missing)."""
    ages = []
    now = time.time()
    for row in feed_status(directory):
        if not row["fetched"]:
            return float("inf")
        ages.append(now - row["fetched"])
    return max(ages) if ages else float("inf")


# ---------------------------------------------------------------------------
# Loading cached feeds into the detection pipeline
# ---------------------------------------------------------------------------

def load_into(intel: ThreatIntel, directory: Optional[Path] = None) -> int:
    """Add every cached IP / domain threat feed to *intel*.  Returns entries added."""
    directory = Path(directory) if directory else intel_dir()
    added = 0
    for spec in FEEDS:
        if spec.kind not in ("ip", "domain", "url", "cert_sha1", "ja3"):
            continue
        cached = _read_cache(directory, spec.name)
        if not cached:
            continue
        entries = cached["entries"]
        if spec.kind in ("cert_sha1", "ja3"):
            for fingerprint, reason in dict(entries).items():
                category = "c2" if "c&c" in str(reason).lower() else spec.category
                intel.add_fingerprint(spec.kind, fingerprint, category, spec.severity,
                                      f"{spec.description} ({reason})")
                added += 1
            continue
        for indicator in entries:
            if spec.kind == "ip":
                if intel.add_network(indicator, spec.category, spec.severity, spec.description):
                    added += 1
            elif spec.kind == "url":
                if intel.add_url(indicator, spec.category, spec.severity, spec.description):
                    added += 1
            else:
                intel.add_domain(indicator, spec.category, spec.severity, spec.description)
                added += 1
    return added


def load_trackers(directory: Optional[Path] = None) -> Dict[str, str]:
    """Return the cached Disconnect tracker map (domain → "Company (Category)")."""
    directory = Path(directory) if directory else intel_dir()
    cached = _read_cache(directory, "disconnect")
    return dict(cached["entries"]) if cached else {}


def load_doh(directory: Optional[Path] = None) -> Tuple[Set[str], Set[str]]:
    """Return (DoH hostnames, DoH IPs) from the cache."""
    directory = Path(directory) if directory else intel_dir()
    domains: Set[str] = set()
    ips: Set[str] = set()
    cached = _read_cache(directory, "doh_domains")
    if cached:
        domains.update(cached["entries"])
    cached = _read_cache(directory, "doh_ipv4")
    if cached:
        ips.update(cached["entries"])
    return domains, ips
