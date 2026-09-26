"""Threat-intel indexing, live-feed parsing, DoH / tracker / false-positive fixes."""
from __future__ import annotations

import json

from pynids.alerts.model import Severity
from pynids.detection.behavioral import BeaconingDetector
from pynids.detection.stealth import DohDetector, LocalhostProbeDetector, TrackerDetector
from pynids.flow.tracker import Flow
from pynids.intel import feeds
from pynids.intel.threat_intel import ThreatIntel
from tests.conftest import make_meta


class TestThreatIntelIndex:
    def test_most_specific_cidr_wins(self):
        ti = ThreatIntel()
        ti.add_network("1.10.16.0/20", "drop", "HIGH", "wide")
        ti.add_network("1.10.16.5/32", "c2", "CRITICAL", "host")
        assert ti.check_ip("1.10.16.5").category == "c2"
        assert ti.check_ip("1.10.20.1").category == "drop"
        assert ti.check_ip("1.10.32.1") is None

    def test_ipv6_and_invalid(self):
        ti = ThreatIntel()
        ti.add_network("2001:678:254::/48", "drop", "HIGH", "v6")
        assert ti.check_ip("2001:678:254::1").category == "drop"
        assert ti.check_ip("not-an-ip") is None
        assert ti.add_network("999.1.1.1", "x", "LOW", "") is False

    def test_domain_exact_and_suffix(self):
        ti = ThreatIntel()
        ti.add_domain("bad.example", "malware", "HIGH", "exact")
        ti.add_domain(".dyn.example", "dyndns", "MEDIUM", "zone")
        assert ti.check_domain("BAD.example.").category == "malware"
        assert ti.check_domain("sub.bad.example") is None
        assert ti.check_domain("a.b.dyn.example").category == "dyndns"
        assert ti.check_domain("dyn.example").category == "dyndns"
        assert ti.check_domain("notdyn.example") is None
        assert ti.domain_entry_count == 2


SPAMHAUS = '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n{"type":"metadata","timestamp":1}\n'
HOSTFILE = "# comment\n127.0.0.1\tlocalhost\n127.0.0.1\tevil-dropper.example\n"
DISCONNECT = json.dumps({"categories": {
    "Advertising": [{"AdCo": {"https://adco.example/": ["adco.example", "adco-cdn.example"]}}],
    "Content": [{"Video": {"https://video.example/": ["video.example"]}}],
    "Cryptomining": [{"Miner": {"https://m.example/": ["coinhive.example"], "performance": "true"}}],
}})


class TestFeeds:
    def test_parsers(self):
        assert feeds._parse_spamhaus_json(SPAMHAUS) == ["1.10.16.0/20"]
        assert feeds._parse_hostfile(HOSTFILE) == ["evil-dropper.example"]
        assert feeds._parse_ip_lines("# x\n1.0.0.1   # cloudflare\n\n8.8.8.8\n") == ["1.0.0.1", "8.8.8.8"]
        trackers = feeds._parse_disconnect(DISCONNECT)
        assert trackers["adco-cdn.example"] == "AdCo (Advertising)"
        assert "video.example" not in trackers  # "Content" is intentionally skipped
        assert trackers["coinhive.example"] == "Miner (Cryptomining)"

    def test_update_and_load(self, tmp_path):
        bodies = {
            "feodo": "162.243.103.246\n", "spamhaus_drop_v4": SPAMHAUS, "spamhaus_drop_v6": "",
            "tor_exits": "171.25.193.25\n", "urlhaus": HOSTFILE, "disconnect": DISCONNECT,
            "doh_domains": "dns.example-doh.net\n", "doh_ipv4": "9.9.9.9 # quad9\n",
        }
        by_url = {spec.url: bodies[spec.name] for spec in feeds.FEEDS}
        results = feeds.update_feeds(tmp_path, fetch=lambda url, timeout: by_url[url])
        status = {r.name: r for r in results}
        assert status["feodo"].ok and status["feodo"].entries == 1
        assert not status["spamhaus_drop_v6"].ok  # empty feed is an error, old cache kept
        ti = ThreatIntel()
        assert feeds.load_into(ti, tmp_path) == 4
        assert ti.check_ip("162.243.103.246").severity == "CRITICAL"
        assert ti.check_domain("evil-dropper.example").category == "malware"
        assert feeds.load_doh(tmp_path) == ({"dns.example-doh.net"}, {"9.9.9.9"})
        assert "adco.example" in feeds.load_trackers(tmp_path)
        assert feeds.oldest_fetch_age(tmp_path) == float("inf")  # v6 missing


class TestTrackerDetector:
    def test_suffix_walk_and_feed_labels(self):
        det = TrackerDetector(extra_domains={"adco.example": "AdCo (Advertising)",
                                             "coinhive.example": "Miner (Cryptomining)"})
        meta = make_meta(dst_port=443)
        hit = list(det.analyze(meta, {"tls": {"sni": "px.eu.adco.example"}}, None))
        assert hit and hit[0].evidence["matched_suffix"] == "adco.example"
        assert hit[0].severity == Severity.LOW
        miner = list(det.analyze(meta, {"quic": {"sni": "coinhive.example"}}, None))
        assert miner[0].severity == Severity.MEDIUM
        assert list(det.analyze(meta, {"tls": {"sni": "notadco.example"}}, None)) == []


class TestDohDetector:
    def test_sni_match(self):
        det = DohDetector()
        meta = make_meta(src_ip="10.0.0.2", dst_ip="104.16.249.249", dst_port=443)
        alerts = list(det.analyze(meta, {"tls": {"sni": "mozilla.cloudflare-dns.com"}}, None))
        assert alerts and alerts[0].rule_id == "STEALTH-ENCRYPTED-DNS"
        # Same resolver again → reported once.
        assert list(det.analyze(meta, {"tls": {"sni": "mozilla.cloudflare-dns.com"}}, None)) == []

    def test_dot_port_and_resolver_ip(self):
        det = DohDetector()
        dot = list(det.analyze(make_meta(dst_ip="203.0.113.5", dst_port=853), {}, None))
        assert dot[0].evidence["method"].startswith("DoT")
        doh = list(det.analyze(make_meta(dst_ip="1.1.1.1", dst_port=443), {}, None))
        assert doh[0].evidence["method"].startswith("DoH")

    def test_plain_dns_to_resolver_is_not_flagged(self):
        det = DohDetector()
        assert list(det.analyze(make_meta(dst_ip="1.1.1.1", dst_port=53, protocol="udp"), {}, None)) == []


class TestFalsePositiveFixes:
    def test_inbound_internet_reply_is_not_a_localhost_probe(self):
        det = LocalhostProbeDetector()
        reply = make_meta(src_ip="142.250.74.46", dst_ip="192.168.1.23", src_port=443,
                          dst_port=50007, protocol="udp")
        assert list(det.analyze(reply, {}, None)) == []

    def test_router_dns_reply_is_not_a_probe(self):
        det = LocalhostProbeDetector()
        reply = make_meta(src_ip="192.168.1.1", dst_ip="192.168.1.23", src_port=53,
                          dst_port=50008, protocol="udp")
        assert list(det.analyze(reply, {}, None)) == []

    def test_udp_probe_reported_once(self):
        det = LocalhostProbeDetector()
        probe = make_meta(src_ip="192.168.1.23", dst_ip="192.168.1.50", src_port=51000,
                          dst_port=9999, protocol="udp")
        assert len(list(det.analyze(probe, {}, None))) == 1
        assert list(det.analyze(probe, {}, None)) == []

    def test_bulk_transfer_is_not_beaconing(self):
        det = BeaconingDetector(min_connections=6)
        alerts = []
        for i in range(20):
            alerts += det.analyze(make_meta(dst_ip="151.101.0.81", dst_port=443,
                                            timestamp=1000 + i * 0.004), {}, None)
        assert alerts == []

    def test_only_new_flows_count_toward_beaconing(self):
        det = BeaconingDetector(min_connections=6)
        flow = Flow(flow_id="f", protocol="tcp", src_ip="a", src_port=1, dst_ip="b", dst_port=2,
                    packet_count=5)
        alerts = []
        for i in range(10):
            alerts += det.analyze(make_meta(timestamp=1000 + i * 30), {}, flow)
        assert alerts == []


class TestLocalhostAttribution:
    def _syn(self, port, app):
        meta = make_meta(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=50000 + port,
                         dst_port=port, protocol="tcp", tcp_flags=0x02)
        return meta, ({"context": {"app": app}} if app else {})

    def test_different_apps_do_not_add_up_to_a_scan(self):
        det = LocalhostProbeDetector(scan_threshold=3)
        out = []
        for port, app in [(3001, "Visual Studio Code"), (3002, "Slack"), (3003, "Docker"), (3004, "Raycast")]:
            out += det.analyze(*self._syn(port, app), None)
        assert out == []  # native apps: no single-probe alerts, no cross-app scan

    def test_browser_scan_is_critical_and_named(self):
        det = LocalhostProbeDetector(scan_threshold=3)
        out = []
        for port in (3001, 5037, 9222):
            out += det.analyze(*self._syn(port, "Google Chrome"), None)
        scan = [a for a in out if a.rule_id == "STEALTH-LOCALHOST-SCAN"]
        assert scan and scan[0].severity == Severity.CRITICAL
        assert "Google Chrome" in scan[0].message

    def test_native_app_scan_is_high(self):
        det = LocalhostProbeDetector(scan_threshold=3)
        out = []
        for port in (3001, 5037, 9222):
            out += det.analyze(*self._syn(port, "SomeTool"), None)
        assert [a.severity for a in out] == [Severity.HIGH]


class TestCorrelationIgnoresPrivacyTelemetry:
    def test_stealth_alerts_do_not_correlate(self):
        from pynids.alerts.manager import AlertManager
        from pynids.alerts.model import Alert, AlertType
        from tests.conftest import AlertCollector

        mgr = AlertManager(dedup_window=0, correlation_threshold=3)
        sink = AlertCollector()
        mgr.register_output(sink)
        for rid in ("STEALTH-TRACKER", "STEALTH-QUIC-INITIAL", "STEALTH-ENCRYPTED-DNS", "STEALTH-BEACON"):
            mgr.add(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.LOW, message=rid,
                          src_ip="192.168.1.23", rule_id=rid))
        assert not [a for a in sink.alerts if a.alert_type == AlertType.CORRELATION]


class TestRealWorldTuning:
    """Regressions for false positives seen on a real Mac's traffic."""

    def test_nettop_parser(self):
        from pynids.enrich.process import parse_nettop
        out = (",bytes_in,\n"
               "com.apple.WebKit.Networking.933,4521,\n"
               "quic4 10.20.5.19:52800<->157.240.253.60:443,49,\n"
               "tcp6 fe80::1%en0.51750<->*.*,,\n"
               "udp4 *:*<->*:*,,\n"
               "WhatsApp.28506,88216725,\n"
               "udp4 10.20.5.19:57660<->*:*,88169751,\n")
        assert parse_nettop(out) == [
            ("udp", 52800, 933, "com.apple.WebKit.Networking"),
            ("tcp", 51750, 933, "com.apple.WebKit.Networking"),
            ("udp", 57660, 28506, "WhatsApp"),
        ]

    def test_download_response_is_not_a_traffic_spike(self):
        from pynids.detection.anomaly import AnomalyDetector
        det = AnomalyDetector(sigma_threshold=2.0, min_rate_pps=0)
        flow = Flow(flow_id="f", protocol="tcp", src_ip="10.0.0.2", src_port=5000,
                    dst_ip="209.85.226.132", dst_port=443)
        out = []
        for i in range(400):
            out += det.analyze(make_meta(src_ip="209.85.226.132", timestamp=i * (0.5 if i < 200 else 0.01)), {}, flow)
        assert out == []

    def test_trivial_rates_never_alert(self):
        from pynids.detection.anomaly import AnomalyDetector
        det = AnomalyDetector(sigma_threshold=1.0)  # default min_rate_pps=100
        out = []
        for w in range(30):
            for _ in range(2 if w < 29 else 14):
                out += det.analyze(make_meta(src_ip="57.144.223.32", timestamp=w * 10 + 1), {}, None)
        assert out == []

    def test_scan_ignores_replies_loopback_multicast_and_browsing(self):
        from pynids.detection.anomaly import PortScanDetector
        det = PortScanDetector(horizontal_threshold=5, vertical_threshold=5)
        reply_flow = Flow(flow_id="r", protocol="udp", src_ip="10.20.5.19", src_port=0,
                          dst_ip="10.20.5.1", dst_port=53, packet_count=2)
        out = []
        for p in range(50000, 50020):  # router DNS answers to many client ports
            out += det.analyze(make_meta(src_ip="10.20.5.1", dst_ip="10.20.5.19", src_port=53,
                                         dst_port=p, protocol="udp"), {}, reply_flow)
        for p in range(3000, 3020):  # local IPC
            out += det.analyze(make_meta(src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=p), {}, None)
        for i in range(30):  # browsing 30 HTTPS sites
            out += det.analyze(make_meta(src_ip="10.20.5.19", dst_ip=f"151.101.{i}.1", dst_port=443), {}, None)
        assert out == []
        # …but sweeping SSH across the LAN is still caught.
        for i in range(6):
            out += det.analyze(make_meta(src_ip="10.20.5.19", dst_ip=f"10.20.5.{100 + i}", dst_port=22), {}, None)
        assert any("host_sweep" in a.tags for a in out)

    def test_download_and_call_media_are_not_exfiltration(self):
        from pynids.detection.behavioral import DataExfiltrationDetector
        det = DataExfiltrationDetector(threshold_bytes=1000)
        download = Flow(flow_id="d", protocol="tcp", src_ip="10.0.0.2", src_port=5000,
                        dst_ip="209.85.226.132", dst_port=443, byte_count=10_000, bytes_from_src=200)
        call = Flow(flow_id="c", protocol="udp", src_ip="10.0.0.2", src_port=5001,
                    dst_ip="57.145.5.54", dst_port=3478, byte_count=10_000, bytes_from_src=9_000)
        assert list(det.analyze(make_meta(), {}, download)) == []
        assert list(det.analyze(make_meta(), {}, call)) == []

    def test_discovery_traffic_is_not_beaconing(self):
        out = []
        det = BeaconingDetector(min_connections=6)
        for dst, port in (("224.0.0.251", 5353), ("255.255.255.255", 10001), ("233.89.188.1", 10001), ("17.253.1.1", 123)):
            for i in range(10):
                out += det.analyze(make_meta(src_ip="10.20.5.1", dst_ip=dst, dst_port=port, protocol="udp",
                                             timestamp=1000 + i * 10.5), {}, None)
        assert out == []

    def test_quic_reported_once_per_site(self):
        from pynids.detection.stealth import QuicHttp3Detector
        det = QuicHttp3Detector()
        out = []
        for i in range(5):  # same site, five CDN edges
            l7 = {"quic": {"packet_type": "Initial", "decrypted": True, "client_hello_complete": True,
                           "sni": "rr4---sn-u15hn5.googlevideo.com", "version": "QUIC v1"}}
            out += det.analyze(make_meta(dst_ip=f"173.194.153.{i}", dst_port=443, protocol="udp"), l7, None)
        assert len(out) == 1
