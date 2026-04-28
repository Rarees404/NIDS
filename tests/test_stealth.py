"""
Tests for PyNIDS X-Ray (stealth) parsers and detectors.

Covers:
  * STUN binding request/response encode-decode round-trips.
  * QUIC long-header version recognition.
  * WebSocket Upgrade and beacon-style HTTP heuristics.
  * Each stealth detector emits the expected alert(s) for canonical input.
  * X-Ray dashboard ingest classifies events into the correct panel and
    keeps counters sane after many events.
"""
from __future__ import annotations

import socket
import time

from pynids.alerts.model import AlertType, Severity
from pynids.alerts.outputs.xray_dashboard import XRayDashboard
from pynids.detection.stealth import (
    BeaconDetector,
    DnsPrefetchDetector,
    LocalhostProbeDetector,
    QuicHttp3Detector,
    TrackerDetector,
    WebRtcLeakDetector,
    WebSocketDetector,
)
from pynids.protocols.dissector import dissect
from pynids.protocols.stealth import (
    classify_ip,
    is_beacon_request,
    is_quic,
    is_stun,
    is_websocket_upgrade,
    parse_quic,
    parse_stun,
)
from tests.conftest import make_meta


# ---------------------------------------------------------------------------
# STUN
# ---------------------------------------------------------------------------

_STUN_MAGIC = b"\x21\x12\xA4\x42"


def _build_stun_binding_response(
    leaked_ip: str = "192.168.1.42",
    leaked_port: int = 54321,
    txid: bytes = b"\x01" * 12,
) -> bytes:
    """Hand-craft a STUN binding success response with XOR-MAPPED-ADDRESS."""
    msg_type = (0x0101).to_bytes(2, "big")
    txid_full = _STUN_MAGIC + txid

    # Build XOR-MAPPED-ADDRESS attribute.
    family = 0x01  # IPv4
    xor_port = leaked_port ^ 0x2112
    raw_ip = socket.inet_aton(leaked_ip)
    xor_ip = bytes(a ^ b for a, b in zip(raw_ip, _STUN_MAGIC))
    attr_value = bytes([0, family]) + xor_port.to_bytes(2, "big") + xor_ip
    attr = (0x0020).to_bytes(2, "big") + len(attr_value).to_bytes(2, "big") + attr_value

    body = attr
    msg_len = len(body).to_bytes(2, "big")
    return msg_type + msg_len + txid_full + body


def _build_stun_binding_request(txid: bytes = b"\x02" * 12) -> bytes:
    msg_type = (0x0001).to_bytes(2, "big")
    txid_full = _STUN_MAGIC + txid
    return msg_type + b"\x00\x00" + txid_full


class TestStunParser:
    def test_classifies_stun_payload(self):
        assert is_stun(_build_stun_binding_request())
        assert not is_stun(b"GET / HTTP/1.1\r\n\r\n")

    def test_parse_binding_request(self):
        info = parse_stun(_build_stun_binding_request())
        assert info["message_type"].startswith("Binding Request")
        assert info["is_response"] is False
        assert info["is_turn"] is False

    def test_xor_mapped_address_round_trip(self):
        payload = _build_stun_binding_response(
            leaked_ip="10.0.0.7", leaked_port=63123
        )
        info = parse_stun(payload)
        assert info["mapped_address"]["ip"] == "10.0.0.7"
        assert info["mapped_address"]["port"] == 63123
        assert info["mapped_address"]["family"] == "IPv4"

    def test_returns_empty_for_non_stun(self):
        assert parse_stun(b"junk\x00bytes") == {}

    def test_dissect_routes_stun_on_arbitrary_port(self):
        # WebRTC routinely picks a high random UDP port — we must still
        # detect STUN by magic cookie, not by port number.
        meta = make_meta(
            dst_port=51234, src_port=50001, protocol="udp",
            payload=_build_stun_binding_response("172.16.0.5", 6000),
        )
        layer7 = dissect(meta)
        assert layer7["app_proto"] == "stun"
        assert layer7["stun"]["mapped_address"]["ip"] == "172.16.0.5"


# ---------------------------------------------------------------------------
# QUIC
# ---------------------------------------------------------------------------

class TestQuicParser:
    def _build_initial(self, version: int = 0x00000001) -> bytes:
        first = 0xC0  # long-header + fixed bit; type Initial(0)
        ver = version.to_bytes(4, "big")
        dcid = b"\x08" + b"\xAA" * 8
        scid = b"\x04" + b"\xBB" * 4
        return bytes([first]) + ver + dcid + scid + b"\x00" * 16

    def test_classifies_quic_long_header(self):
        assert is_quic(self._build_initial())
        assert not is_quic(b"\x00\x00\x00\x01" + b"\x00" * 8)

    def test_extracts_version_and_cids(self):
        info = parse_quic(self._build_initial(0x00000001))
        assert info["packet_type"] == "Initial"
        assert "QUIC v1" in info["version"]
        assert info["dcid"] == "aa" * 8
        assert info["scid"] == "bb" * 4

    def test_dissect_routes_quic(self):
        meta = make_meta(dst_port=443, protocol="udp", payload=self._build_initial())
        layer7 = dissect(meta)
        assert layer7["app_proto"] == "quic"


# ---------------------------------------------------------------------------
# HTTP-layer stealth heuristics
# ---------------------------------------------------------------------------

class TestWebSocketAndBeacon:
    def test_websocket_upgrade(self):
        info = {
            "direction": "request",
            "headers": {
                "upgrade": "websocket",
                "connection": "Upgrade, keep-alive",
            },
        }
        assert is_websocket_upgrade(info)

    def test_websocket_upgrade_negative(self):
        assert not is_websocket_upgrade({"direction": "request", "headers": {}})

    def test_beacon_post_no_accept(self):
        info = {
            "direction": "request",
            "method": "POST",
            "uri": "/log",
            "headers": {"content-type": "text/plain", "content-length": "120"},
            "content_length": "120",
        }
        assert is_beacon_request(info)

    def test_beacon_pixel_get(self):
        info = {
            "direction": "request",
            "method": "GET",
            "uri": "/__utm.gif?utmac=UA-1234",
            "headers": {},
        }
        assert is_beacon_request(info)

    def test_beacon_negative_normal_get(self):
        info = {
            "direction": "request",
            "method": "GET",
            "uri": "/index.html",
            "headers": {"accept": "text/html"},
        }
        assert not is_beacon_request(info)


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------

class TestClassifyIp:
    def test_loopback(self):
        assert classify_ip("127.0.0.1") == "loopback"
        assert classify_ip("::1") == "loopback"

    def test_private(self):
        assert classify_ip("10.5.6.7") == "private"
        assert classify_ip("192.168.0.1") == "private"

    def test_public(self):
        assert classify_ip("8.8.8.8") == "public"

    def test_unknown(self):
        assert classify_ip(None) == "unknown"
        assert classify_ip("not.an.ip") == "unknown"


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

class TestWebRtcLeakDetector:
    def test_emits_high_severity_for_private_ip_leak(self):
        det = WebRtcLeakDetector()
        layer7 = {"stun": parse_stun(_build_stun_binding_response("192.168.1.50", 50000))}
        meta = make_meta(dst_ip="74.125.250.129", dst_port=19302, protocol="udp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert "192.168.1.50" in alerts[0].evidence["leaked_ip"]
        assert alerts[0].rule_id == "STEALTH-WEBRTC-LEAK"

    def test_low_severity_for_public_reflexive(self):
        det = WebRtcLeakDetector()
        layer7 = {"stun": parse_stun(_build_stun_binding_response("8.8.4.4", 1234))}
        meta = make_meta(dst_ip="74.125.250.129", dst_port=19302, protocol="udp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.LOW
        assert alerts[0].rule_id == "STEALTH-WEBRTC-REFLEXIVE"

    def test_request_only_yields_informational(self):
        det = WebRtcLeakDetector()
        layer7 = {"stun": parse_stun(_build_stun_binding_request())}
        meta = make_meta(dst_ip="74.125.250.129", dst_port=19302, protocol="udp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert alerts[0].rule_id == "STEALTH-WEBRTC-STUN"


class TestLocalhostProbeDetector:
    def test_loopback_syn_emits_high(self):
        det = LocalhostProbeDetector()
        meta = make_meta(
            src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=12345,
            protocol="tcp", tcp_flags=0x02,
        )
        alerts = list(det.analyze(meta, {}, None))
        assert any(a.severity == Severity.HIGH for a in alerts)
        assert any(a.rule_id == "STEALTH-LOCALHOST-PROBE" for a in alerts)

    def test_repeated_ports_trigger_scan_alert(self):
        det = LocalhostProbeDetector(scan_threshold=3, scan_window=10.0)
        emitted = []
        for port in (12345, 23456, 34567, 45678):
            meta = make_meta(
                src_ip="127.0.0.1", dst_ip="127.0.0.1", dst_port=port,
                protocol="tcp", tcp_flags=0x02, timestamp=time.time(),
            )
            emitted.extend(det.analyze(meta, {}, None))
        assert any(a.rule_id == "STEALTH-LOCALHOST-SCAN" for a in emitted)
        assert any(a.severity == Severity.CRITICAL for a in emitted)

    def test_quiet_port_on_private_subnet_is_ignored(self):
        det = LocalhostProbeDetector()
        meta = make_meta(
            src_ip="10.0.0.5", dst_ip="10.0.0.1", dst_port=443,
            protocol="tcp", tcp_flags=0x02,
        )
        assert list(det.analyze(meta, {}, None)) == []

    def test_public_destination_ignored(self):
        det = LocalhostProbeDetector()
        meta = make_meta(
            src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=53,
            protocol="udp",
        )
        assert list(det.analyze(meta, {}, None)) == []


class TestQuicHttp3Detector:
    def test_emits_once_per_endpoint(self):
        det = QuicHttp3Detector()
        layer7 = {"quic": {"version": "QUIC v1 (RFC 9000)", "packet_type": "Initial",
                            "dcid": "aa", "scid": "bb"}}
        meta = make_meta(dst_ip="142.250.74.142", dst_port=443, protocol="udp")
        first = list(det.analyze(meta, layer7, None))
        second = list(det.analyze(meta, layer7, None))
        assert len(first) == 1
        assert len(second) == 0


class TestWebSocketDetector:
    def test_upgrade_yields_alert(self):
        det = WebSocketDetector()
        layer7 = {"http": {
            "websocket_upgrade": True, "host": "ws.example.com",
            "uri": "/socket", "user_agent": "Chrome",
        }}
        meta = make_meta(dst_ip="93.184.216.34", dst_port=443, protocol="tcp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert alerts[0].rule_id == "STEALTH-WEBSOCKET"


class TestBeaconDetector:
    def test_beacon_yields_alert(self):
        det = BeaconDetector()
        layer7 = {"http": {
            "beacon_suspect": True, "host": "stats.example.com",
            "uri": "/collect", "method": "POST", "headers": {},
            "content_length": "200",
        }}
        meta = make_meta(dst_ip="93.184.216.34", dst_port=443, protocol="tcp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert alerts[0].rule_id == "STEALTH-BEACON"


class TestDnsPrefetchDetector:
    def test_burst_above_threshold_emits_alert(self):
        det = DnsPrefetchDetector(burst_threshold=4, window_seconds=10.0)
        emitted = []
        for i, name in enumerate(("a.com", "b.com", "c.com", "d.com", "e.com")):
            layer7 = {"dns": {"query_name": name, "is_response": False}}
            meta = make_meta(src_ip="10.0.0.5", protocol="udp", timestamp=time.time())
            emitted.extend(det.analyze(meta, layer7, None))
        assert any(a.rule_id == "STEALTH-DNS-PREFETCH" for a in emitted)


class TestTrackerDetector:
    def test_matches_by_dns(self):
        det = TrackerDetector()
        layer7 = {"dns": {"query_name": "www.google-analytics.com", "is_response": False}}
        meta = make_meta(src_ip="10.0.0.5", protocol="udp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert "Google Analytics" in alerts[0].message

    def test_matches_by_tls_sni(self):
        det = TrackerDetector()
        layer7 = {"tls": {"sni": "connect.facebook.net"}}
        meta = make_meta(dst_ip="31.13.65.1", dst_port=443, protocol="tcp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1
        assert "facebook" in alerts[0].evidence["host"]

    def test_dedup_per_host(self):
        det = TrackerDetector()
        layer7 = {"tls": {"sni": "doubleclick.net"}}
        meta = make_meta(dst_ip="142.250.74.142", dst_port=443, protocol="tcp")
        first = list(det.analyze(meta, layer7, None))
        second = list(det.analyze(meta, layer7, None))
        assert len(first) == 1
        assert len(second) == 0

    def test_no_match_for_normal_site(self):
        det = TrackerDetector()
        layer7 = {"tls": {"sni": "example.com"}}
        meta = make_meta(dst_ip="93.184.216.34", dst_port=443, protocol="tcp")
        assert list(det.analyze(meta, layer7, None)) == []


# ---------------------------------------------------------------------------
# X-Ray dashboard ingest
# ---------------------------------------------------------------------------

class TestXRayDashboardIngest:
    def _make_alert(self, **kw):
        from pynids.alerts.model import Alert
        defaults = dict(
            alert_type=AlertType.BEHAVIORAL,
            severity=Severity.LOW,
            message="test",
            src_ip="10.0.0.5",
            dst_ip="74.125.250.129",
            dst_port=19302,
            protocol="udp",
            tags=[],
            evidence={},
        )
        defaults.update(kw)
        return Alert(**defaults)

    def test_classifies_each_kind(self):
        d = XRayDashboard(iface="x", refresh_hz=1.0)
        cases = [
            (self._make_alert(rule_id="STEALTH-WEBRTC-LEAK", tags=["webrtc"],
                              evidence={"leaked_ip": "192.168.1.5",
                                        "leaked_address_class": "private"}),
             "webrtc"),
            (self._make_alert(rule_id="STEALTH-LOCALHOST-PROBE", tags=["localhost_probe"],
                              evidence={"destination_class": "loopback",
                                        "transport": "tcp"}),
             "localhost"),
            (self._make_alert(rule_id="STEALTH-QUIC-INITIAL", tags=["quic"],
                              evidence={"version": "QUIC v1"}),
             "quic"),
            (self._make_alert(rule_id="STEALTH-WEBSOCKET", tags=["websocket"],
                              evidence={"host": "ws.example.com", "path": "/x"}),
             "websocket"),
            (self._make_alert(rule_id="STEALTH-TRACKER", tags=["tracker"],
                              evidence={"host": "google-analytics.com",
                                        "category": "Google Analytics",
                                        "source": "TLS SNI"}),
             "tracker"),
            (self._make_alert(rule_id="STEALTH-BEACON", tags=["beacon"]),
             "beacon"),
            (self._make_alert(rule_id="STEALTH-DNS-PREFETCH", tags=["dns_prefetch"]),
             "prefetch"),
        ]
        for alert, expected in cases:
            d.emit(alert)
            assert d._counts[expected] >= 1, f"missing count for {expected}"
        assert d._counts["total"] == len(cases)

    def test_render_does_not_raise_when_empty_or_full(self):
        d = XRayDashboard(iface="x", refresh_hz=1.0)
        # Empty render must succeed.
        layout = d._render()
        assert layout is not None
        # Pump 50 events; render again must still succeed.
        for i in range(50):
            d.emit(self._make_alert(
                rule_id="STEALTH-WEBRTC-LEAK", tags=["webrtc"],
                evidence={"leaked_ip": f"192.168.0.{i}",
                          "leaked_address_class": "private"},
                src_ip=f"10.0.0.{i}",
            ))
        layout = d._render()
        assert layout is not None
        assert d._counts["webrtc"] == 50
