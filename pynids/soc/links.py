"""
"Open in …" links to analyst tools that have no free API (or whose web UI
shows more than the API).  Nothing is sent anywhere until the analyst clicks.
"""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import quote, quote_plus

from .ioc import HASH_TYPES, Ioc
from .sources.free import registered_domain

_IP = [
    ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{v}"),
    ("AbuseIPDB", "https://www.abuseipdb.com/check/{v}"),
    ("Shodan", "https://www.shodan.io/host/{v}"),
    ("Censys", "https://search.censys.io/hosts/{v}"),
    ("GreyNoise", "https://viz.greynoise.io/ip/{v}"),
    ("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={v}"),
    ("IBM X-Force", "https://exchange.xforce.ibmcloud.com/ip/{v}"),
    ("AlienVault OTX", "https://otx.alienvault.com/indicator/ip/{v}"),
    ("ThreatFox", "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}"),
    ("urlscan.io", "https://urlscan.io/search/#ip%3A%22{v}%22"),
    ("IPinfo", "https://ipinfo.io/{v}"),
    ("Spur (VPN / proxy)", "https://spur.us/context/{v}"),
    ("bgp.he.net", "https://bgp.he.net/ip/{v}"),
]
_DOMAIN = [
    ("VirusTotal", "https://www.virustotal.com/gui/domain/{v}"),
    ("urlscan.io", "https://urlscan.io/search/#domain%3A{v}"),
    ("Cisco Talos", "https://talosintelligence.com/reputation_center/lookup?search={v}"),
    ("IBM X-Force", "https://exchange.xforce.ibmcloud.com/url/{v}"),
    ("AlienVault OTX", "https://otx.alienvault.com/indicator/domain/{v}"),
    ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search={v}"),
    ("ThreatFox", "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}"),
    ("crt.sh", "https://crt.sh/?q={v}"),
    ("SecurityTrails", "https://securitytrails.com/domain/{v}/dns"),
    ("DNSDumpster", "https://dnsdumpster.com/"),
    ("WHOIS (DomainTools)", "https://whois.domaintools.com/{r}"),
    ("MXToolbox", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{v}"),
    ("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search?url={v}"),
    ("Wayback Machine", "https://web.archive.org/web/*/{v}"),
]
_URL = [
    ("VirusTotal (search)", "https://www.virustotal.com/gui/search/{q}"),
    ("urlscan.io (search)", "https://urlscan.io/search/#page.url%3A%22{q}%22"),
    ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search={q}"),
    ("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search?url={q}"),
    ("Wayback Machine", "https://web.archive.org/web/*/{v}"),
]
_HASH = [
    ("VirusTotal", "https://www.virustotal.com/gui/file/{v}"),
    ("MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search={m}"),
    ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query={v}"),
    ("Joe Sandbox", "https://www.joesandbox.com/search?q={v}"),
    ("Triage", "https://tria.ge/s?q={v}"),
    ("AlienVault OTX", "https://otx.alienvault.com/indicator/file/{v}"),
    ("ThreatFox", "https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}"),
    ("ANY.RUN (TI lookup)", "https://intelligence.any.run/analysis/lookup#{{%22query%22:%22{v}%22}}"),
]
_EMAIL = [
    ("Have I Been Pwned", "https://haveibeenpwned.com/account/{q}"),
    ("Google (exact)", "https://www.google.com/search?q=%22{q}%22"),
]
_ASN = [
    ("bgp.he.net", "https://bgp.he.net/{v}"),
    ("IPinfo", "https://ipinfo.io/{v}"),
    ("Shodan", "https://www.shodan.io/search?query=asn%3A{v}"),
    ("PeeringDB", "https://www.peeringdb.com/search?q={n}"),
]
_CVE = [
    ("NVD", "https://nvd.nist.gov/vuln/detail/{v}"),
    ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={v}"),
    ("MITRE", "https://www.cve.org/CVERecord?id={v}"),
    ("Exploit-DB", "https://www.exploit-db.com/search?cve={n}"),
]


def links(ioc: Ioc) -> List[Dict[str, str]]:
    table = {"ipv4": _IP, "ipv6": _IP, "domain": _DOMAIN, "url": _URL, "email": _EMAIL,
             "asn": _ASN, "cve": _CVE}.get(ioc.type)
    if table is None and len(ioc.value) in HASH_TYPES:
        table = _HASH
    if not table:
        return []
    v = ioc.value
    fields = {
        "v": quote(v, safe=":/"), "q": quote_plus(v),
        "r": registered_domain(v) if ioc.type == "domain" else v,
        "m": ("sha256%3A" if ioc.type == "sha256" else ioc.type + "%3A") + v if len(v) in HASH_TYPES else v,
        "n": v[2:] if ioc.type == "asn" else v[4:] if ioc.type == "cve" else v,
    }
    return [{"label": label, "url": tpl.format(**fields)} for label, tpl in table]
