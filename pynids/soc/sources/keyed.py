"""Sources that need a (free) API key."""
from __future__ import annotations

import base64
import json
from typing import Any, Dict
from urllib.parse import quote, urlencode

from ..ioc import Ioc, is_public_ip
from . import HASHES, IPS, Ctx, Result, Source, SourceError, fmt_ts


class VirusTotal(Source):
    name = "virustotal"
    label = "VirusTotal"
    description = "Verdicts from ~70 antivirus engines and URL scanners; file metadata, names and first-seen dates."
    homepage = "https://www.virustotal.com/"
    types = IPS + ("domain", "url") + HASHES[:3]
    key = "virustotal"
    key_help = "Free key: sign up at https://www.virustotal.com, then Profile → API key (4 lookups/min)"
    per_minute = 4

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if ioc.type in IPS and not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        if ioc.type in IPS:
            path = f"ip_addresses/{ioc.value}"
        elif ioc.type == "domain":
            path = f"domains/{ioc.value}"
        elif ioc.type == "url":
            path = "urls/" + base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        else:
            path = f"files/{ioc.value}"
        data, res = self.get_json(ctx, f"https://www.virustotal.com/api/v3/{path}", {"x-apikey": ctx.key or ""})
        if not data:
            res.message = "VirusTotal has never seen this"
            return res
        a: Dict[str, Any] = (data.get("data") or {}).get("attributes") or {}
        stats = a.get("last_analysis_stats") or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        res.row("Detections", f"{mal} malicious, {sus} suspicious of {total} engines")
        if mal >= 3:
            res.verdict = "malicious"
        elif mal or sus:
            res.verdict = "suspicious"
        elif stats.get("harmless") or stats.get("undetected"):
            res.verdict = "clean"
        res.row("Community reputation", a.get("reputation"))
        res.row("Last analysed", fmt_ts(a.get("last_analysis_date")))
        engines = [f"{k}: {v.get('result')}" for k, v in (a.get("last_analysis_results") or {}).items()
                   if v.get("category") in ("malicious", "suspicious")]
        res.row("Flagged by", engines[:25])
        if ioc.type in IPS:
            res.row("Network", a.get("network"))
            res.row("Owner", a.get("as_owner"))
            res.row("ASN", a.get("asn"))
            res.row("Country", a.get("country"))
            res.pivot("asn", f"AS{a['asn']}" if a.get("asn") else None, "ASN")
        elif ioc.type == "domain":
            res.row("Registrar", a.get("registrar"))
            res.row("Created", fmt_ts(a.get("creation_date")))
            res.row("Categories", ", ".join(sorted(set((a.get("categories") or {}).values()))))
            for rec in a.get("last_dns_records") or []:
                if rec.get("type") in ("A", "AAAA"):
                    res.pivot("ipv4" if rec["type"] == "A" else "ipv6", rec.get("value"), "DNS")
        elif ioc.type == "url":
            res.row("Final URL", a.get("last_final_url"))
            res.row("Page title", a.get("title"))
            res.row("Categories", ", ".join(sorted(set((a.get("categories") or {}).values()))))
            res.pivot("url", a.get("last_final_url") if a.get("last_final_url") != ioc.value else None,
                      "redirects to")
        else:
            res.row("Name", a.get("meaningful_name"))
            res.row("Type", a.get("type_description"))
            res.row("Size", f"{a['size']:,} bytes" if a.get("size") else None)
            res.row("First submitted", fmt_ts(a.get("first_submission_date")))
            res.row("Threat label", (a.get("popular_threat_classification") or {}).get("suggested_threat_label"))
            res.row("Other names", (a.get("names") or [])[:15])
            for h in ("md5", "sha1", "sha256"):
                if a.get(h) and a[h] != ioc.value:
                    res.pivot(h, a[h])
            if a.get("ssdeep"):
                res.row("ssdeep", a["ssdeep"])
            if a.get("tlsh"):
                res.row("TLSH", a["tlsh"])
        res.tags = list(a.get("tags") or [])[:20]
        return res


class AbuseIpDb(Source):
    name = "abuseipdb"
    label = "AbuseIPDB"
    description = "Crowd-sourced abuse reports for an IP: confidence score, report count, ISP and usage type."
    homepage = "https://www.abuseipdb.com/"
    types = IPS
    key = "abuseipdb"
    key_help = "Free key: https://www.abuseipdb.com/register, then Account → API (1,000 checks/day)"

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        qs = urlencode({"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": ""})
        data, res = self.get_json(ctx, f"https://api.abuseipdb.com/api/v2/check?{qs}", {"Key": ctx.key or ""})
        d = (data or {}).get("data") or {}
        score = d.get("abuseConfidenceScore")
        res.row("Abuse confidence", f"{score}%" if score is not None else None)
        res.row("Reports (90 days)", d.get("totalReports"))
        res.row("Distinct reporters", d.get("numDistinctUsers"))
        res.row("Last reported", (d.get("lastReportedAt") or "")[:16].replace("T", " "))
        res.row("ISP", d.get("isp"))
        res.row("Usage type", d.get("usageType"))
        res.row("Domain", d.get("domain"))
        res.row("Country", d.get("countryCode"))
        res.row("Tor exit node", "yes" if d.get("isTor") else None)
        comments = [str(r.get("comment") or "").strip() for r in (d.get("reports") or [])[:8] if r.get("comment")]
        res.row("Recent report comments", comments)
        res.pivot("domain", d.get("domain"), "ISP domain")
        if d.get("isTor"):
            res.tags.append("tor")
        if score is not None:
            res.verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return res


class Otx(Source):
    name = "otx"
    label = "AlienVault OTX"
    description = "Threat-intel 'pulses' (community reports) that mention the indicator, with malware families."
    homepage = "https://otx.alienvault.com/"
    types = IPS + ("domain", "url") + HASHES[:3]
    key = "otx"
    key_help = "Free key: https://otx.alienvault.com, then Settings → OTX Key"

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        if ioc.type in IPS and not is_public_ip(ioc.value):
            return self.result(status="unsupported", message="private or reserved address — not sent out")
        section = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url"}.get(ioc.type, "file")
        data, res = self.get_json(ctx, f"https://otx.alienvault.com/api/v1/indicators/{section}/"
                                       f"{quote(ioc.value, safe='')}/general", {"X-OTX-API-KEY": ctx.key or ""},
                                  not_found=(400, 404))
        if not data:
            return res
        pulses = (data.get("pulse_info") or {}).get("pulses") or []
        count = (data.get("pulse_info") or {}).get("count", len(pulses))
        res.row("Pulses", count)
        res.row("Pulse names", [p.get("name") for p in pulses[:15]])
        families = sorted({f.get("display_name") for p in pulses for f in p.get("malware_families") or []
                           if isinstance(f, dict) and f.get("display_name")})
        res.row("Malware families", ", ".join(families))
        attack = sorted({t.get("display_name") for p in pulses for t in p.get("attack_ids") or []
                         if isinstance(t, dict) and t.get("display_name")})
        res.row("ATT&CK techniques", ", ".join(attack[:15]))
        res.row("Country", data.get("country_name"))
        res.row("ASN", data.get("asn"))
        res.tags = sorted({t for p in pulses for t in p.get("tags") or []})[:20]
        validation = [v.get("name") for v in data.get("validation") or []]
        res.row("Allowlisted by OTX", ", ".join(v for v in validation if v))
        if validation:
            res.verdict = "clean"
        elif count:
            res.verdict = "malicious" if families else "suspicious"
        else:
            res.verdict = "clean"
        return res


class _AbuseCh(Source):
    key = "abusech"
    key_help = "Free Auth-Key (one for all abuse.ch services): https://auth.abuse.ch/"

    def post(self, ctx: Ctx, url: str, form: Dict[str, str] = None, payload: Dict[str, Any] = None):
        if payload is not None:
            body, ctype = json.dumps(payload).encode(), "application/json"
        else:
            body, ctype = urlencode(form or {}).encode(), "application/x-www-form-urlencoded"
        data, res = self.get_json(ctx, url, {"Auth-Key": ctx.key or "", "Content-Type": ctype}, "POST", body)
        status = (data or {}).get("query_status")
        if status in ("no_results", "hash_not_found", "illegal_hash", "no_result", "not_found"):
            res.status = "not_found"
            return None, res
        if status and status != "ok" and status not in ("is_host", "is_ip_address"):
            raise SourceError(f"abuse.ch: {status}")
        return data, res


class UrlHaus(_AbuseCh):
    name = "urlhaus"
    label = "URLhaus (abuse.ch)"
    description = "Malware-distribution URLs and hosts, and the payloads they served."
    homepage = "https://urlhaus.abuse.ch/"
    types = ("url", "domain", "ipv4", "md5", "sha256")

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        base = "https://urlhaus-api.abuse.ch/v1/"
        if ioc.type == "url":
            data, res = self.post(ctx, base + "url/", {"url": ioc.value})
        elif ioc.type in HASHES:
            data, res = self.post(ctx, base + "payload/", {f"{ioc.type}_hash": ioc.value})
        else:
            data, res = self.post(ctx, base + "host/", {"host": ioc.value})
        if not data:
            return res
        res.verdict = "malicious"
        if ioc.type == "url":
            res.row("Status", data.get("url_status"))
            res.row("Threat", data.get("threat"))
            res.row("First seen", data.get("date_added"))
            res.row("Reporter", data.get("reporter"))
            res.tags = list(data.get("tags") or [])
            payloads = data.get("payloads") or []
            res.row("Payloads", [f"{p.get('filename') or '?'} · {p.get('file_type')} · "
                                 f"{p.get('signature') or 'unknown'} · {p.get('response_sha256')}" for p in payloads[:10]])
            for p in payloads:
                res.pivot("sha256", p.get("response_sha256"), "payload")
        elif ioc.type in HASHES:
            res.row("File type", data.get("file_type"))
            res.row("Signature", data.get("signature"))
            res.row("First seen", data.get("firstseen"))
            res.row("URLs serving it", data.get("url_count"))
            for u in (data.get("urls") or [])[:50]:
                res.pivot("url", u.get("url"), "served from")
        else:
            urls = data.get("urls") or []
            res.row("Malware URLs on this host", data.get("url_count", len(urls)))
            res.row("Online now", sum(1 for u in urls if u.get("url_status") == "online"))
            res.row("First seen", data.get("firstseen"))
            res.row("Blocklists", ", ".join(f"{k}: {v}" for k, v in (data.get("blacklists") or {}).items()))
            res.tags = sorted({t for u in urls for t in u.get("tags") or []})[:20]
            for u in urls[:50]:
                res.pivot("url", u.get("url"), u.get("threat") or "")
        return res


class ThreatFox(_AbuseCh):
    name = "threatfox"
    label = "ThreatFox (abuse.ch)"
    description = "C2 servers and malware IOCs, labelled by family (Cobalt Strike, Emotet, …) with confidence."
    homepage = "https://threatfox.abuse.ch/"
    types = IPS + ("domain", "url") + HASHES[:3]

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        payload = ({"query": "search_hash", "hash": ioc.value} if ioc.type in HASHES
                   else {"query": "search_ioc", "search_term": ioc.value, "exact_match": False})
        data, res = self.post(ctx, "https://threatfox-api.abuse.ch/api/v1/", payload=payload)
        rows = (data or {}).get("data") or []
        if not isinstance(rows, list) or not rows:
            res.status = "not_found"
            return res
        res.verdict = "malicious"
        res.row("Matches", len(rows))
        res.row("Malware", ", ".join(sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})))
        res.row("Threat type", ", ".join(sorted({r.get("threat_type_desc") or r.get("threat_type")
                                                  for r in rows if r.get("threat_type")})))
        res.row("Confidence", max((r.get("confidence_level") or 0) for r in rows))
        res.row("First seen", min((r.get("first_seen") or "~") for r in rows))
        res.row("IOCs", [f"{r.get('ioc')} · {r.get('malware_printable')} · {r.get('first_seen')}" for r in rows[:15]])
        res.tags = sorted({t for r in rows for t in (r.get("tags") or [])})[:20]
        return res


class MalwareBazaar(_AbuseCh):
    name = "malwarebazaar"
    label = "MalwareBazaar (abuse.ch)"
    description = "Malware samples: family, file type, delivery method and vendor verdicts for a hash."
    homepage = "https://bazaar.abuse.ch/"
    types = HASHES[:3]

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:
        data, res = self.post(ctx, "https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": ioc.value})
        rows = (data or {}).get("data") or []
        if not rows:
            res.status = "not_found"
            return res
        d = rows[0]
        res.verdict = "malicious"
        res.row("File name", d.get("file_name"))
        res.row("File type", f"{d.get('file_type')} ({d.get('file_type_mime')})")
        res.row("Size", f"{d['file_size']:,} bytes" if d.get("file_size") else None)
        res.row("Family", d.get("signature"))
        res.row("First seen", d.get("first_seen"))
        res.row("Delivery", d.get("delivery_method"))
        res.row("Origin country", d.get("origin_country"))
        res.row("imphash", d.get("imphash"))
        res.row("ssdeep", d.get("ssdeep"))
        res.row("TLSH", d.get("tlsh"))
        res.tags = list(d.get("tags") or [])
        for h in ("md5_hash", "sha1_hash", "sha256_hash"):
            if d.get(h) and d[h] != ioc.value:
                res.pivot(h.split("_")[0], d[h])
        return res
