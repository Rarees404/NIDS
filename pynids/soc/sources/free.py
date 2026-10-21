"""Keyless sources (some accept an optional key for higher limits)."""
from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlsplit

from ...host.dossier import parse_internetdb, parse_rdap
from ..ioc import Ioc, is_public_ip
from . import HASHES, IPS, Ctx, Result, Source, SourceError

# Second-level labels under which registries sell names (example.co.uk).
_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go", "gob", "mil", "nic", "ltd", "plc"}


def registered_domain(host: str) -> str:
    """Best-effort registrable domain (no public-suffix list): a.b.example.co.uk → example.co.uk."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _iso_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------

class Rdap(Source):
    name = "rdap"
    label = "RDAP (WHOIS)"
    description = "Who owns an IP range, ASN or domain; registration and expiry dates."
    homepage = "https://about.rdap.org/"
    types = IPS + ("domain", "asn")
    ttl = 24 * 3600

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if ioc.type in IPS:
            if not is_public_ip(ioc.value):
                return self.result(status="unsupported", message="private or reserved address — not sent out")
            data, res = self.get_json(ctx, f"https://rdap.org/ip/{ioc.value}")
            if data:
                info = parse_rdap(data)
                for label, key in (("Network", "network"), ("Range", "cidr"), ("Owner", "owner"),
                                   ("Country", "country"), ("Registered", "registered"),
                                   ("Updated", "updated"), ("Abuse contact", "abuse_email"),
                                   ("Remarks", "remarks")):
                    res.row(label, info.get(key) or (info.get("range") if key == "cidr" else None))
                res.pivot("email", info.get("abuse_email"), "abuse contact")
                res.verdict = "info"
            return res
        if ioc.type == "asn":
            data, res = self.get_json(ctx, f"https://rdap.org/autnum/{ioc.value[2:]}")
            if data:
                info = parse_rdap(data)
                res.row("Name", data.get("name"))
                res.row("Owner", info.get("owner"))
                res.row("Country", data.get("country"))
                res.row("Registered", info.get("registered"))
                res.row("Abuse contact", info.get("abuse_email"))
                res.verdict = "info"
            return res
        domain = registered_domain(ioc.value)
        data, res = self.get_json(ctx, f"https://rdap.org/domain/{domain}")
        if not data:
            return res
        res.verdict = "info"
        if domain != ioc.value:
            res.row("Registered domain", domain)
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or []}
        created = _iso_date(events.get("registration"))
        for e in data.get("entities") or []:
            if "registrar" in (e.get("roles") or []):
                vcard = (e.get("vcardArray") or [None, []])[1] or []
                name = next((v[3] for v in vcard if isinstance(v, list) and len(v) > 3 and v[0] == "fn"), None)
                res.row("Registrar", name or e.get("handle"))
        if created:
            age = (datetime.now(timezone.utc) - created).days
            res.row("Created", f"{created:%Y-%m-%d} ({age} days ago)")
            if age < 30:
                res.worse("suspicious")
                res.tags.append("newly registered")
        res.row("Updated", (events.get("last changed") or "")[:10])
        res.row("Expires", (events.get("expiration") or "")[:10])
        res.row("Status", ", ".join(data.get("status") or []))
        ns = [n.get("ldhName", "").lower() for n in data.get("nameservers") or [] if n.get("ldhName")]
        res.row("Name servers", ", ".join(ns))
        for n in ns:
            res.pivot("domain", n, "name server")
        dnssec = (data.get("secureDNS") or {}).get("delegationSigned")
        if dnssec is not None:
            res.row("DNSSEC", "signed" if dnssec else "unsigned")
        return res


class DnsOverHttps(Source):
    name = "dns"
    label = "DNS records"
    description = ("A, AAAA, CNAME, MX, NS, TXT records of a domain, or the reverse name of an IP, "
                   "resolved through Google Public DNS over HTTPS — your own resolver isn't involved.")
    homepage = "https://developers.google.com/speed/public-dns/docs/doh/json"
    types = IPS + ("domain",)
    ttl = 3600
    RECORDS = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")

    def _ask(self, ctx: Ctx, name: str, rtype: str) -> Dict[str, Any]:
        status, text = ctx.http("GET", f"https://dns.google/resolve?name={quote(name)}&type={rtype}",
                                {}, None, ctx.timeout)
        if status >= 400:
            raise SourceError(f"HTTP {status} from dns.google")
        return json.loads(text)

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        res = self.result(verdict="info")
        if ioc.type in IPS:
            ptr = ipaddress.ip_address(ioc.value).reverse_pointer
            data = self._ask(ctx, ptr, "PTR")
            res.raw = {"PTR": data}
            names = [a["data"].rstrip(".") for a in data.get("Answer") or [] if a.get("type") == 12]
            res.row("Reverse DNS", ", ".join(names) or "none")
            for n in names:
                res.pivot("domain", n, "PTR")
            return res
        res.raw = {}
        for rtype in self.RECORDS:
            data = self._ask(ctx, ioc.value, rtype)
            res.raw[rtype] = data
            if rtype == "A" and data.get("Status") == 3:
                res.status = "not_found"
                res.message = "NXDOMAIN — the domain does not exist (or no longer resolves)"
                res.tags.append("nxdomain")
                return res
            answers = [a for a in data.get("Answer") or [] if a.get("name", "").rstrip(".").lower() == ioc.value
                       or rtype in ("A", "AAAA")]
            values = []
            for a in answers:
                value = a.get("data", "")
                if rtype == "MX":
                    value = value.split()[-1] if value else value
                values.append(value.rstrip(".") if rtype != "TXT" else value.strip('"'))
            if rtype in ("A", "AAAA"):
                values = [v for v in values if _is_ip(v)]
            values = list(dict.fromkeys(values))
            if values:
                res.row(rtype, values if rtype == "TXT" else ", ".join(values))
            for v in values:
                if rtype in ("A", "AAAA"):
                    res.pivot("ipv4" if rtype == "A" else "ipv6", v, rtype)
                elif rtype in ("CNAME", "MX", "NS"):
                    res.pivot("domain", v.lower(), rtype)
        spf = [t for t in (dict(res.summary).get("TXT") or []) if t.lower().startswith("v=spf1")]
        if spf:
            res.row("SPF", spf[0])
        if not any(k in ("A", "AAAA", "CNAME") for k, _ in res.summary):
            res.tags.append("no address records")
        return res


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class InternetDb(Source):
    name = "internetdb"
    label = "Shodan InternetDB"
    description = "Open ports, hostnames, tags (vpn, tor, c2 …) and known CVEs from Shodan's passive scans."
    homepage = "https://internetdb.shodan.io/"
    types = IPS

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        data, res = self.get_json(ctx, f"https://internetdb.shodan.io/{ioc.value}")
        if not data:
            res.message = "not seen by Shodan's scanners"
            return res
        info = parse_internetdb(data)
        res.verdict = "info"
        res.row("Open ports", ", ".join(str(p) for p in data.get("ports") or []) or "none")
        res.row("Hostnames", ", ".join(data.get("hostnames") or []))
        res.row("Known CVEs", ", ".join((data.get("vulns") or [])[:30]))
        res.row("CPEs", ", ".join((data.get("cpes") or [])[:15]))
        res.tags = list(info.get("tags") or [])
        if any(t in ("c2", "malware", "compromised") for t in res.tags):
            res.worse("malicious")
        elif any(t in ("tor", "proxy", "vpn", "scanner") for t in res.tags):
            res.worse("suspicious")
        for h in data.get("hostnames") or []:
            res.pivot("domain", h, "hostname")
        for cve in (data.get("vulns") or [])[:30]:
            res.pivot("cve", cve)
        return res


class GreyNoise(Source):
    name = "greynoise"
    label = "GreyNoise"
    description = ("Is this IP internet background noise (mass scanners, crawlers) or a known benign "
                   "service (RIOT)?  Separates targeted activity from noise.")
    homepage = "https://viz.greynoise.io/"
    types = IPS
    key = "greynoise"
    key_optional = True
    key_help = "Free community key: https://viz.greynoise.io/signup (works without one, at a lower limit)"

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        headers = {"key": ctx.key} if ctx.key else {}
        data, res = self.get_json(ctx, f"https://api.greynoise.io/v3/community/{ioc.value}", headers)
        if not data:
            res.message = "not observed scanning the internet"
            return res
        cls = data.get("classification")
        res.row("Classification", cls)
        res.row("Name", data.get("name"))
        res.row("Internet noise", "yes — mass scanning" if data.get("noise") else "no")
        res.row("Known benign service (RIOT)", "yes" if data.get("riot") else "no")
        res.row("Last seen", data.get("last_seen"))
        res.row("Message", data.get("message"))
        res.verdict = {"malicious": "malicious", "benign": "clean"}.get(cls, "info")
        if data.get("riot"):
            res.verdict = "clean"
        if data.get("noise"):
            res.tags.append("scanner")
        return res


class Urlscan(Source):
    name = "urlscan"
    label = "urlscan.io search"
    description = ("Existing urlscan.io scans that contacted this domain, IP, URL or file hash — with "
                   "screenshots.  Searches only; nothing is submitted for scanning.")
    homepage = "https://urlscan.io/"
    types = IPS + ("domain", "url", "sha256")
    key = "urlscan"
    key_optional = True
    key_help = "Free key: https://urlscan.io/user/signup (search works without one, at a lower limit)"

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if ioc.type in IPS and not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        esc = ioc.value.replace("\\", "\\\\").replace('"', '\\"')
        # page.* = scans *of* this site/IP, not every page that loaded something from it.
        q = {"domain": f'page.domain:"{esc}"', "url": f'page.url:"{esc}"', "sha256": f"hash:{esc}"}.get(
            ioc.type, f'page.ip:"{esc}"')
        headers = {"API-Key": ctx.key} if ctx.key else {}
        data, res = self.get_json(ctx, f"https://urlscan.io/api/v1/search/?q={quote(q)}&size=50", headers)
        results = (data or {}).get("results") or []
        res.row("Scans found", (data or {}).get("total", len(results)))
        if not results:
            res.status = "not_found"
            return res
        res.verdict = "info"
        rows = []
        for r in results[:10]:
            page, task = r.get("page") or {}, r.get("task") or {}
            rows.append({"time": (task.get("time") or "")[:16].replace("T", " "), "url": page.get("url"),
                         "ip": page.get("ip"), "country": page.get("country"), "server": page.get("server"),
                         "report": r.get("result", "").replace("/api/v1/result/", "/result/"),
                         "screenshot": r.get("screenshot")})
        res.row("Latest scans", rows)
        for r in results:
            page = r.get("page") or {}
            res.pivot("ipv4" if ":" not in (page.get("ip") or ":") else "ipv6", page.get("ip"), "page IP")
            res.pivot("domain", page.get("domain"), "page domain")
        return res


class CrtSh(Source):
    name = "crtsh"
    label = "Certificate Transparency (crt.sh)"
    description = "Every public TLS certificate issued for the domain and its subdomains."
    homepage = "https://crt.sh/"
    types = ("domain",)
    ttl = 24 * 3600

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        ctx.timeout = max(ctx.timeout, 25.0)  # crt.sh is slow on popular domains
        # "%.example.com" matches subdomains only; the apex needs its own query.
        apex, res = self.get_json(ctx, f"https://crt.sh/?q={quote(ioc.value)}&output=json")
        subs, res_subs = self.get_json(ctx, f"https://crt.sh/?q={quote('%.' + ioc.value)}&output=json")
        res.raw = {"exact": res.raw, "subdomains": res_subs.raw}
        res.truncated = res.truncated or res_subs.truncated
        res.status = "ok"
        certs: List[Dict[str, Any]] = list({c.get("id"): c for c in (apex if isinstance(apex, list) else [])
                                            + (subs if isinstance(subs, list) else [])}.values())
        if not certs:
            res.status = "not_found"
            res.message = "no certificates logged"
            return res
        res.verdict = "info"
        names = set()
        for c in certs:
            for n in str(c.get("name_value") or "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n:
                    names.add(n)
        dates = sorted(c.get("not_before") or "" for c in certs if c.get("not_before"))
        issuers = {}
        for c in certs:
            issuer = str(c.get("issuer_name") or "")
            org = next((p.split("=", 1)[1] for p in issuer.split(", ") if p.startswith("O=")), issuer)
            issuers[org] = issuers.get(org, 0) + 1
        res.row("Certificates", len(certs))
        res.row("First issued", dates[0][:10] if dates else None)
        res.row("Latest issued", dates[-1][:10] if dates else None)
        res.row("Issuers", ", ".join(f"{k} ({v})" for k, v in sorted(issuers.items(), key=lambda kv: -kv[1])[:6]))
        res.row("Names", f"{len(names)} unique host names")
        for n in sorted(names)[:150]:
            res.pivot("domain", n, "certificate name")
        if dates and dates[0][:10] >= time.strftime("%Y-%m-%d", time.gmtime(time.time() - 14 * 86400)):
            res.tags.append("first certificate in the last 14 days")
            res.worse("suspicious")
        return res


def url_host(url: str) -> Optional[str]:
    return urlsplit(url).hostname
