"""
Regression tests for detection fixes:

* distinct built-in detections are no longer collapsed by deduplication
* the volumetric detector compares a window against *earlier* windows
* TLS is recognised on any port, and reports the version really offered
* the server's first flight (ServerHello, certificate) is parsed and judged
* scans paced below the burst window are caught through failed connections
"""
from __future__ import annotations

import datetime
import ssl

import pytest

from pynids.alerts.manager import AlertManager
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.detection.anomaly import AnomalyDetector, PortScanDetector
from pynids.detection.behavioral import HttpAttackDetector
from pynids.engine import BUILTIN_RULES, DetectionEngine
from pynids.flow.tracker import FlowTracker
from pynids.protocols.dissector import cert_matches_name, dissect

from .conftest import AlertCollector, make_meta

CLIENT, SERVER = "192.168.1.10", "93.184.216.34"


# ---------------------------------------------------------------------------
# Deduplication / correlation identity
# ---------------------------------------------------------------------------

class TestDetectionIdentity:
    def test_built_in_detections_have_distinct_ids(self):
        sqli = Alert(AlertType.BEHAVIORAL, Severity.HIGH, "a", tags=["sqli", "webapp"])
        xss = Alert(AlertType.BEHAVIORAL, Severity.HIGH, "b", tags=["xss", "webapp"])
        rule = Alert(AlertType.SIGNATURE, Severity.HIGH, "c", rule_id="SIG-1", tags=["sqli"])
        assert sqli.detection_id == "detector:sqli"
        assert xss.detection_id == "detector:xss"
        assert rule.detection_id == "SIG-1"

    def test_different_attacks_on_one_pair_are_all_emitted(self):
        sink = AlertCollector()
        mgr = AlertManager(correlation_threshold=99)
        mgr.register_output(sink)
        det = HttpAttackDetector()
        for uri in ("/a?id=1'%20OR%20'1'='1", "/b?q=<script>alert(1)</script>", "/c?f=../../etc/passwd"):
            meta = make_meta(src_ip=CLIENT, dst_ip=SERVER, tcp_flags=0x18,
                             payload=f"GET {uri} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            for alert in det.analyze(meta, dissect(meta), None):
                mgr.add(alert)
        assert len(sink.alerts) == 3

    def test_same_detection_is_still_deduplicated(self):
        sink = AlertCollector()
        mgr = AlertManager()
        mgr.register_output(sink)
        for _ in range(5):
            mgr.add(Alert(AlertType.BEHAVIORAL, Severity.HIGH, "x", src_ip=CLIENT, dst_ip=SERVER,
                          dst_port=80, tags=["sqli"]))
        assert len(sink.alerts) == 1

    def test_correlation_counts_built_in_detections_separately(self):
        sink = AlertCollector()
        mgr = AlertManager(correlation_threshold=3)
        mgr.register_output(sink)
        for tag in ("sqli", "brute_force", "vertical_scan"):
            mgr.add(Alert(AlertType.BEHAVIORAL, Severity.HIGH, tag, src_ip="203.0.113.9",
                          dst_ip="10.0.0.2", tags=[tag]))
        assert len(sink.of_type(AlertType.CORRELATION)) == 1


# ---------------------------------------------------------------------------
# Volumetric spikes
# ---------------------------------------------------------------------------

class TestVolumetric:
    @staticmethod
    def _feed(det, src, start, pps, seconds):
        out = []
        for i in range(int(pps * seconds)):
            out += det.analyze(make_meta(src_ip=src, timestamp=start + i / pps), {}, None)
        return out

    def test_spike_over_a_quiet_baseline_alerts_once_per_window(self):
        det = AnomalyDetector()  # defaults: 10 s windows, 100 pkt/s floor
        assert self._feed(det, "1.2.3.4", 1000.0, 5, 60) == []
        alerts = self._feed(det, "1.2.3.4", 1060.0, 3000, 9)
        assert len(alerts) == 1
        assert alerts[0].evidence["ewma_rate"] == pytest.approx(5.0, abs=0.5)

    def test_flood_from_an_unknown_source_alerts(self):
        det = AnomalyDetector()
        assert len(self._feed(det, "5.5.5.5", 2000.0, 5000, 5)) == 1

    def test_busy_but_steady_source_does_not_alert(self):
        det = AnomalyDetector()
        alerts = self._feed(det, "9.9.9.9", 3000.0, 400, 10)   # first window: the baseline is unknown
        alerts = self._feed(det, "9.9.9.9", 3010.0, 400, 120)  # the same rate, sustained
        assert alerts == []

    def test_silent_windows_lower_the_baseline(self):
        det = AnomalyDetector(min_rate_pps=0)
        self._feed(det, "7.7.7.7", 100.0, 50, 10)
        list(det.analyze(make_meta(src_ip="7.7.7.7", timestamp=1000.0), {}, None))
        stats = det._per_source["7.7.7.7"]
        assert stats.ewma_rate < 1.0 and len(stats.history) == 60


# ---------------------------------------------------------------------------
# TLS: real handshakes produced by the ssl module
# ---------------------------------------------------------------------------

def _self_signed(tmp_path, common_name="internal.example", days=30, start_days_ago=1):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=start_days_ago)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return str(cert_file), str(key_file)


def _handshake(tmp_path, sni, max_version, **cert_args):
    """(ClientHello bytes, server first-flight bytes) of a real handshake."""
    cert_file, key_file = _self_signed(tmp_path, **cert_args)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_file, key_file)
    server_ctx.maximum_version = max_version
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE

    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=sni)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    client_hello = c_out.read()
    s_in.write(client_hello)
    with pytest.raises(ssl.SSLWantReadError):
        server.do_handshake()
    return client_hello, s_out.read()


def _segments(data, size=700):
    return [data[i:i + size] for i in range(0, len(data), size)]


class TestTlsAnyPort:
    def test_client_hello_is_recognised_on_any_port(self, tmp_path):
        hello, _ = _handshake(tmp_path, "c2.example.org", ssl.TLSVersion.TLSv1_3)
        for port in (443, 4443, 8080, 993, 9001):
            meta = make_meta(src_ip=CLIENT, dst_ip=SERVER, src_port=50000 + port, dst_port=port,
                             payload=hello, tcp_flags=0x18)
            layer7 = dissect(meta)
            assert layer7["app_proto"] == "tls", port
            assert layer7["tls"]["sni"] == "c2.example.org", port
            assert layer7["tls"]["ja3"]

    def test_offered_version_comes_from_supported_versions(self, tmp_path):
        hello, _ = _handshake(tmp_path, "a.example.org", ssl.TLSVersion.TLSv1_3)
        tls = dissect(make_meta(dst_port=443, payload=hello, tcp_flags=0x18))["tls"]
        assert tls["tls_version"] == "TLS 1.3"
        assert tls["legacy_version"] == "TLS 1.2"
        assert "TLS 1.3" in tls["supported_versions"]

    def test_plain_http_on_a_tls_port_is_still_http(self):
        meta = make_meta(dst_port=4443, payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", tcp_flags=0x18)
        assert dissect(meta)["app_proto"] == "http"

    def test_binary_noise_is_not_tls(self):
        meta = make_meta(dst_port=4443, payload=b"\x16\x03\x01" + b"\xff" * 40, tcp_flags=0x18)
        assert dissect(meta) == {}


class TestTlsServerFlight:
    def _server_packets(self, flight, port=4443, sport=51000, ts=None):
        return [make_meta(src_ip=SERVER, dst_ip=CLIENT, src_port=port, dst_port=sport, payload=seg,
                          tcp_flags=0x18, timestamp=ts) for seg in _segments(flight)]

    def test_certificate_is_reassembled_across_segments(self, tmp_path):
        _, flight = _handshake(tmp_path, "internal.example", ssl.TLSVersion.TLSv1_2)
        results = [dissect(m)["tls"] for m in self._server_packets(flight, sport=51001)]
        assert len(results) > 1 and all(r == {"partial": True} for r in results[:-1])
        tls = results[-1]
        assert tls["direction"] == "server" and tls["negotiated_version"] == "TLS 1.2"
        assert len(tls["ja3s"]) == 32 and tls["cipher_suite"].startswith("0x")
        cert = tls["cert"]
        assert cert["subject_cn"] == "internal.example" and cert["self_signed"] is True
        assert cert["san"] == ["internal.example"] and cert["expired"] is False
        assert len(cert["sha256"]) == 64 and cert["validity_days"] == pytest.approx(30, abs=0.1)

    def test_tls13_reports_the_version_and_no_certificate(self, tmp_path):
        _, flight = _handshake(tmp_path, "internal.example", ssl.TLSVersion.TLSv1_3)
        # A post-quantum key share makes the ServerHello itself span segments.
        results = [dissect(m).get("tls") for m in self._server_packets(flight, sport=51002)]
        tls = next(r for r in results if r and "negotiated_version" in r)
        assert tls["negotiated_version"] == "TLS 1.3" and "cert" not in tls

    def test_expired_certificate(self, tmp_path):
        _, flight = _handshake(tmp_path, "old.example", ssl.TLSVersion.TLSv1_2,
                               common_name="old.example", days=10, start_days_ago=40)
        tls = [dissect(m)["tls"] for m in self._server_packets(flight, sport=51003)][-1]
        assert tls["cert"]["expired"] is True

    def test_name_matching(self):
        cert = {"san": ["example.org", "*.example.org"], "subject_cn": "example.org"}
        assert cert_matches_name(cert, "www.example.org") is True
        assert cert_matches_name(cert, "EXAMPLE.org.") is True
        assert cert_matches_name(cert, "a.b.example.org") is False
        assert cert_matches_name(cert, "example.com") is False
        assert cert_matches_name(cert, None) is None
        assert cert_matches_name({"subject_cn": "only-cn.example"}, "only-cn.example") is True

    def test_engine_flags_self_signed_and_mismatching_certificate(self, tmp_path):
        hello, flight = _handshake(tmp_path, "login.bank.example", ssl.TLSVersion.TLSv1_2,
                                   common_name="internal.example")
        sink = AlertCollector()
        mgr = AlertManager()
        mgr.register_output(sink)
        engine = DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr)
        engine.process_packet(make_meta(src_ip=CLIENT, dst_ip=SERVER, src_port=51004, dst_port=8443,
                                        payload=hello, tcp_flags=0x18))
        for meta in self._server_packets(flight, port=8443, sport=51004):
            engine.process_packet(meta)
        fired = {a.rule_id: a for a in sink.alerts}
        assert "SIG-TLS-002" in fired and "SIG-TLS-003" in fired
        assert "login.bank.example" in fired["SIG-TLS-003"].message
        flow = engine.flows(limit=1)[0]
        assert flow["tls"]["sni"] == "login.bank.example"
        assert flow["tls"]["cert_subject"] == "internal.example"
        assert flow["tls"]["cert_matches_sni"] is False and flow["tls"]["ja3s"]

    def test_matching_certificate_raises_no_mismatch(self, tmp_path):
        hello, flight = _handshake(tmp_path, "internal.example", ssl.TLSVersion.TLSv1_2)
        sink = AlertCollector()
        mgr = AlertManager()
        mgr.register_output(sink)
        engine = DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr)
        engine.process_packet(make_meta(src_ip=CLIENT, dst_ip=SERVER, src_port=51005, dst_port=443,
                                        payload=hello, tcp_flags=0x18))
        for meta in self._server_packets(flight, port=443, sport=51005):
            engine.process_packet(meta)
        assert "SIG-TLS-003" not in {a.rule_id for a in sink.alerts}


# ---------------------------------------------------------------------------
# Slow scans: failed connections
# ---------------------------------------------------------------------------

SYN, SYNACK, RST = 0x02, 0x12, 0x14
SCANNER, VICTIM = "10.0.0.66", "10.0.0.5"


class TestFailedConnectionScan:
    @staticmethod
    def _run(det, tracker, packets):
        out = []
        for meta in packets:
            out += det.analyze(meta, {}, tracker.update(meta))
        return out

    def test_slow_scan_of_closed_ports(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = []
        for i in range(40):  # one port every 20 s: far below the 60 s burst threshold
            t = 1000.0 + i * 20
            packets.append(make_meta(src_ip=SCANNER, dst_ip=VICTIM, src_port=40000 + i, dst_port=1 + i,
                                     tcp_flags=SYN, timestamp=t))
            packets.append(make_meta(src_ip=VICTIM, dst_ip=SCANNER, src_port=1 + i, dst_port=40000 + i,
                                     tcp_flags=RST, timestamp=t + 0.01))
        alerts = self._run(det, tracker, packets)
        assert len(alerts) == 1
        assert alerts[0].evidence["method"] == "failed_connections"
        assert alerts[0].src_ip == SCANNER and alerts[0].dst_ip == VICTIM
        assert "vertical_scan" in alerts[0].tags

    def test_slow_scan_of_filtered_ports(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = [make_meta(src_ip=SCANNER, dst_ip=VICTIM, src_port=40000 + i, dst_port=1 + i,
                             tcp_flags=SYN, timestamp=1000.0 + i * 20) for i in range(40)]
        alerts = self._run(det, tracker, packets)
        assert len(alerts) == 1 and alerts[0].evidence["last_failure"] == "unanswered"

    def test_slow_sweep_of_one_port_across_hosts(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = [make_meta(src_ip=SCANNER, dst_ip=f"10.0.1.{i + 1}", src_port=40000 + i, dst_port=445,
                             tcp_flags=SYN, timestamp=1000.0 + i * 20) for i in range(40)]
        alerts = self._run(det, tracker, packets)
        assert len(alerts) == 1 and "host_sweep" in alerts[0].tags

    def test_last_probes_are_counted_when_the_scanner_goes_quiet(self):
        det, tracker = PortScanDetector(vertical_threshold=15), FlowTracker()
        packets = [make_meta(src_ip=SCANNER, dst_ip=VICTIM, src_port=40000 + i, dst_port=1 + i,
                             tcp_flags=SYN, timestamp=1000.0 + i * 20) for i in range(15)]
        assert self._run(det, tracker, packets) == []      # the 15th is still waiting for an answer
        det.prune(1000.0 + 15 * 20 + 60)
        other = make_meta(src_ip="10.0.0.9", dst_ip="10.0.0.1", dst_port=53, protocol="udp", timestamp=1400.0)
        assert len(self._run(det, tracker, [other])) == 1

    def test_successful_connections_are_not_failures(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = []
        for i in range(40):
            t = 1000.0 + i * 20
            packets.append(make_meta(src_ip=SCANNER, dst_ip=VICTIM, src_port=40000 + i, dst_port=1 + i,
                                     tcp_flags=SYN, timestamp=t))
            packets.append(make_meta(src_ip=VICTIM, dst_ip=SCANNER, src_port=1 + i, dst_port=40000 + i,
                                     tcp_flags=SYNACK, timestamp=t + 0.01))
        assert self._run(det, tracker, packets) == []

    def test_dead_websites_are_not_a_sweep(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = [make_meta(src_ip="192.168.1.10", dst_ip=f"93.184.{i}.34", src_port=40000 + i, dst_port=443,
                             tcp_flags=SYN, timestamp=1000.0 + i * 20) for i in range(40)]
        assert self._run(det, tracker, packets) == []

    def test_state_is_released(self):
        det, tracker = PortScanDetector(), FlowTracker()
        packets = [make_meta(src_ip=SCANNER, dst_ip=VICTIM, src_port=40000 + i, dst_port=1 + i,
                             tcp_flags=SYN, timestamp=1000.0 + i) for i in range(5)]
        self._run(det, tracker, packets)
        det.prune(1000.0 + 7200)
        assert not det._state
