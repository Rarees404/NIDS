"""SOC workbench: indicator parsing, sources (against canned responses), cache, API."""
from __future__ import annotations

import json
import stat
import threading
import time

import pytest

from pynids.service.api import ServiceContext, make_server
from pynids.service.live import LiveState
from pynids.soc.ioc import classify, defang, extract, refang
from pynids.soc.keys import KeyStore
from pynids.soc.links import links
from pynids.soc.sources import Ctx
from pynids.soc.sources.free import CrtSh, DnsOverHttps, Rdap, registered_domain
from pynids.soc.sources.keyed import AbuseIpDb, MalwareBazaar, ThreatFox, VirusTotal
from pynids.soc.workbench import LocalSource, Workbench
from tests.test_service import call


class FakeHttp:
    """Answers by URL substring; records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body))
        for needle, (status, payload) in self.routes.items():
            if needle in url:
                return status, payload if isinstance(payload, str) else json.dumps(payload)
        return 404, ""


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

class TestIoc:
    @pytest.mark.parametrize("raw,kind,value", [
        ("hxxps://evil[.]com/login?a=1", "url", "https://evil.com/login?a=1"),
        ("8.8.8[.]8", "ipv4", "8.8.8.8"),
        (" '185.220.101.4', ", "ipv4", "185.220.101.4"),
        ("2001:4860:4860:0::8888", "ipv6", "2001:4860:4860::8888"),
        ("44D88612FEA8A8F36DE82E1278ABB02F", "md5", "44d88612fea8a8f36de82e1278abb02f"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("as 13335", "asn", "AS13335"),
        ("cve-2024-3400", "cve", "CVE-2024-3400"),
        ("Bob[@]Phish[.]co.uk", "email", "Bob@phish.co.uk"),
        ("evil.com/path", "url", "http://evil.com/path"),
        ("EXAMPLE.COM.", "domain", "example.com"),
        ("bücher.de", "domain", "xn--bcher-kva.de"),
    ])
    def test_classify(self, raw, kind, value):
        ioc = classify(raw)
        assert (ioc.type, ioc.value) == (kind, value)
        assert ioc.original == raw.strip()

    @pytest.mark.parametrize("raw", ["", "not an ioc", "hello world", "1.2.3", "http://", "a\nb.com"])
    def test_not_indicators(self, raw):
        assert classify(raw) is None

    def test_defang_roundtrip(self):
        for value, kind in [("https://evil.com/a.b", "url"), ("1.2.3.4", "ipv4"),
                            ("x@evil.com", "email"), ("evil.co.uk", "domain")]:
            safe = defang(value, kind)
            assert safe != value and "evil.com" not in safe
            assert refang(safe) == value
        assert defang("https://evil.com/a.b", "url") == "hxxps://evil[.]com/a.b"

    def test_extract_from_report(self):
        text = ("Host 10.0.0.5 beaconed to hxxp://c2[.]bad-domain[.]ru/gate.php and 185.220.101.4.\n"
                "Dropped payload.exe sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, "
                "mail from attacker@phish.example.com (see CVE-2023-23397), also update.microsoft.com, fe80::1. "
                "Config in settings.yaml. Repeat: 185.220.101.4")
        got = [(i.type, i.value) for i in extract(text)]
        assert got == [
            ("ipv4", "10.0.0.5"), ("url", "http://c2.bad-domain.ru/gate.php"), ("ipv4", "185.220.101.4"),
            ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("email", "attacker@phish.example.com"), ("cve", "CVE-2023-23397"),
            ("domain", "update.microsoft.com"), ("ipv6", "fe80::1"),
        ]

    def test_registered_domain(self):
        assert registered_domain("a.b.example.com") == "example.com"
        assert registered_domain("login.example.co.uk") == "example.co.uk"

    def test_links(self):
        urls = [x["url"] for x in links(classify("8.8.8.8"))]
        assert "https://www.virustotal.com/gui/ip-address/8.8.8.8" in urls
        assert all(u.startswith("https://") for u in urls)
        assert links(classify("CVE-2024-3400"))[0]["url"].endswith("CVE-2024-3400")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def run(source, raw, routes, key="k"):
    http = FakeHttp(routes)
    return source.query(classify(raw), Ctx(http=http, key=key)), http


class TestSources:
    def test_virustotal_file(self):
        body = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 55, "suspicious": 1, "undetected": 10, "harmless": 0},
            "last_analysis_results": {"EngineA": {"category": "malicious", "result": "Trojan.X"}},
            "meaningful_name": "invoice.exe", "sha256": "e" * 64, "md5": "a" * 32, "size": 1234,
            "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla"},
            "tags": ["peexe"]}}}
        res, http = run(VirusTotal(), "a" * 32, {"/files/": (200, body)})
        assert res.verdict == "malicious"
        assert dict(res.summary)["Detections"].startswith("55 malicious")
        assert {"type": "sha256", "value": "e" * 64, "label": ""} in res.pivots
        assert res.raw == body  # nothing lost
        assert http.calls[0][2]["x-apikey"] == "k"

    def test_virustotal_url_id_and_not_found(self):
        res, http = run(VirusTotal(), "https://evil.com/x", {})
        assert res.status == "not_found"
        assert "/urls/aHR0cHM6Ly9ldmlsLmNvbS94" in http.calls[0][1]  # base64url, no padding

    def test_private_ip_never_sent(self):
        res, http = run(VirusTotal(), "192.168.1.10", {})
        assert res.status == "unsupported" and not http.calls

    def test_abuseipdb_score(self):
        res, _ = run(AbuseIpDb(), "185.220.101.4", {"abuseipdb": (200, {"data": {
            "abuseConfidenceScore": 100, "totalReports": 900, "isTor": True, "isp": "Tor"}})})
        assert res.verdict == "malicious" and "tor" in res.tags

    def test_rdap_young_domain(self):
        created = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime(time.time() - 5 * 86400))
        res, http = run(Rdap(), "login.paypa1-secure.com", {"rdap.org/domain/paypa1-secure.com": (200, {
            "events": [{"eventAction": "registration", "eventDate": created}],
            "nameservers": [{"ldhName": "NS1.EVILDNS.NET"}], "status": ["active"]})})
        assert res.verdict == "suspicious" and "newly registered" in res.tags
        assert {"type": "domain", "value": "ns1.evildns.net", "label": "name server"} in res.pivots

    def test_dns_nxdomain_and_records(self):
        res, _ = run(DnsOverHttps(), "gone.example", {"dns.google": (200, {"Status": 3})})
        assert res.status == "not_found" and "nxdomain" in res.tags

        def answer(t, data):
            return {"Status": 0, "Answer": [{"name": "example.com.", "type": t, "data": data}]}
        http_routes = {
            "type=AAAA": (200, answer(28, "2606:2800::1")), "type=A": (200, answer(1, "93.184.215.14")),
            "type=CNAME": (200, {"Status": 0}), "type=MX": (200, answer(15, "10 mx.example.com.")),
            "type=NS": (200, answer(2, "a.iana-servers.net.")), "type=TXT": (200, answer(16, '"v=spf1 -all"')),
        }
        res, _ = run(DnsOverHttps(), "example.com", http_routes)
        s = dict(res.summary)
        assert s["A"] == "93.184.215.14" and s["MX"] == "mx.example.com" and s["SPF"] == "v=spf1 -all"
        assert {"type": "ipv4", "value": "93.184.215.14", "label": "A"} in res.pivots

    def test_crtsh_merges_apex_and_subdomains(self):
        routes = {"q=%25.": (200, [{"id": 2, "name_value": "www.example.com\n*.example.com",
                                    "not_before": "2020-01-01T00:00:00", "issuer_name": "C=US, O=Let's Encrypt"}]),
                  "q=example.com": (200, [{"id": 1, "name_value": "example.com",
                                           "not_before": "2019-01-01T00:00:00", "issuer_name": "O=DigiCert"}])}
        res, _ = run(CrtSh(), "example.com", routes)
        s = dict(res.summary)
        assert s["Certificates"] == 2 and s["First issued"] == "2019-01-01"
        assert set(res.raw) == {"exact", "subdomains"}

    def test_threatfox_and_bazaar(self):
        res, http = run(ThreatFox(), "185.220.101.4", {"threatfox": (200, {"query_status": "ok", "data": [
            {"ioc": "185.220.101.4:443", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc",
             "confidence_level": 100, "first_seen": "2024-01-01", "tags": ["CobaltStrike"]}]})})
        assert res.verdict == "malicious" and "Cobalt Strike" in dict(res.summary)["Malware"]
        assert http.calls[0][2]["Auth-Key"] == "k"
        res, _ = run(MalwareBazaar(), "a" * 64, {"mb-api": (200, {"query_status": "hash_not_found"})})
        assert res.status == "not_found"


# ---------------------------------------------------------------------------
# Workbench
# ---------------------------------------------------------------------------

class TestWorkbench:
    def test_cache_keys_history_rate_limit(self, tmp_path):
        http = FakeHttp({"abuseipdb": (200, {"data": {"abuseConfidenceScore": 50}})})
        keys = KeyStore(tmp_path / "keys.json")
        wb = Workbench(tmp_path / "db.sqlite", keys=keys, http=http, sources=[AbuseIpDb(), VirusTotal()])

        assert wb.lookup("abuseipdb", "ipv4", "1.1.1.1")["status"] == "needs_key"
        keys.set("abuseipdb", "secret")
        assert stat.S_IMODE((tmp_path / "keys.json").stat().st_mode) == 0o600
        first = wb.lookup("abuseipdb", "ipv4", "1.1.1.1")
        assert first["verdict"] == "suspicious" and not first["cached"]
        assert wb.lookup("abuseipdb", "ipv4", "1.1.1.1")["cached"]
        assert len(http.calls) == 1
        wb.lookup("abuseipdb", "ipv4", "1.1.1.1", refresh=True)
        assert len(http.calls) == 2

        wb.parse("1.1.1.1")
        assert wb.history()[0]["value"] == "1.1.1.1" and wb.history()[0]["verdict"] == "suspicious"

        keys.set("virustotal", "v")
        for i in range(4):
            wb.lookup("virustotal", "ipv4", f"8.8.8.{i}")
        limited = wb.lookup("virustotal", "ipv4", "8.8.8.9")
        assert limited["status"] == "rate_limited" and limited["retry_after"] > 0

    def test_errors_are_contained(self, tmp_path):
        def boom(*a):
            raise OSError("network down")
        wb = Workbench(None, http=boom, sources=[Rdap()])
        res = wb.lookup("rdap", "domain", "example.com")
        assert res["status"] == "error" and "network down" in res["message"]

    def test_local_source(self, tmp_path):
        from pynids.intel.threat_intel import ThreatIntel
        intel = ThreatIntel()
        intel.add_domain("evil.example", category="c2", severity="HIGH", description="test C2")
        local = LocalSource(intel=lambda: intel, live=LiveState())
        res = local.query(classify("www.example.org"), Ctx(http=FakeHttp({})))
        assert res.status == "ok" and dict(res.summary)["Threat-intel feed"] == "no match"
        res = local.query(classify("hxxps://login.evil[.]example/x"), Ctx(http=FakeHttp({})))
        assert res.verdict == "malicious" and "on your blocklists" in res.tags


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def soc_api(tmp_path):
    http = FakeHttp({"internetdb": (200, {"ip": "8.8.8.8", "ports": [53, 443], "tags": [], "hostnames": ["dns.google"]})})
    from pynids.soc.sources.free import InternetDb
    wb = Workbench(tmp_path / "db.sqlite", keys=KeyStore(tmp_path / "k.json"), http=http,
                   sources=[InternetDb(), VirusTotal()])
    ctx = ServiceContext(live=LiveState(), token="t0ken", db_path=tmp_path / "events.db", workbench=wb)
    server = make_server(ctx, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], wb
    server.shutdown()
    server.server_close()


class TestSocApi:
    def test_flow(self, soc_api):
        port, wb = soc_api
        assert call(port, "/api/soc/sources", token=None)[0] == 401
        code, parsed = call(port, "/api/soc/parse", method="POST", body={"text": "8.8.8[.]8"})
        assert code == 200 and parsed["single"]
        ioc = parsed["iocs"][0]
        assert ioc["type"] == "ipv4" and ioc["sources"] == ["internetdb", "virustotal"] and ioc["links"]
        code, res = call(port, "/api/soc/lookup", method="POST",
                         body={"source": "internetdb", "type": "ipv4", "value": "8.8.8.8"})
        assert code == 200 and dict(res["summary"])["Open ports"] == "53, 443"
        assert call(port, "/api/soc/lookup", method="POST", body={"source": "nope", "type": "ipv4",
                                                                   "value": "8.8.8.8"})[0] == 404

    def test_keys_never_returned(self, soc_api):
        port, wb = soc_api
        assert call(port, "/api/soc/keys", method="POST", body={"name": "bogus", "value": "x"})[0] == 400
        code, res = call(port, "/api/soc/keys", method="POST", body={"name": "virustotal", "value": "SECRET"})
        assert code == 200 and res == {"name": "virustotal", "configured": True}
        _, sources = call(port, "/api/soc/sources")
        assert "SECRET" not in json.dumps(sources)
        assert next(s for s in sources if s["name"] == "virustotal")["configured"]
        call(port, "/api/soc/keys/virustotal", method="DELETE")
        assert not wb.keys.configured("virustotal")
