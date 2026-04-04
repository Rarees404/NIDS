"""Tests for behavioral detectors: DNS tunneling, HTTP attacks, exfiltration, beaconing."""
from __future__ import annotations

import time
import pytest
from pynids.detection.behavioral import (
    DnsTunnelingDetector,
    HttpAttackDetector,
    DataExfiltrationDetector,
    BeaconingDetector,
)
from pynids.alerts.model import AlertType
from pynids.flow.tracker import Flow, FlowState
from tests.conftest import make_meta


# ---------------------------------------------------------------------------
# DNS tunneling
# ---------------------------------------------------------------------------

class TestDnsTunnelingDetector:
    def test_high_entropy_name_triggers(self):
        det = DnsTunnelingDetector(entropy_threshold=3.5, length_threshold=200)
        layer7 = {
            "dns": {
                "query_name": "a3f9x2k1q8z7v4n5.randombase64noise.tunnel.example.com",
                "name_entropy": 3.9,
                "name_length": 52,
                "subdomain_depth": 5,
            }
        }
        alerts = list(det.analyze(make_meta(protocol="udp", dst_port=53), layer7, None))
        assert len(alerts) == 1
        assert "dns_tunneling" in alerts[0].tags
        assert alerts[0].mitre_technique == "T1071.004"

    def test_long_name_triggers(self):
        det = DnsTunnelingDetector(entropy_threshold=100.0, length_threshold=30)
        layer7 = {
            "dns": {
                "query_name": "a" * 35 + ".tunnel.example.com",
                "name_entropy": 1.0,  # Low entropy, but long
                "name_length": 55,
                "subdomain_depth": 3,
            }
        }
        alerts = list(det.analyze(make_meta(protocol="udp", dst_port=53), layer7, None))
        assert len(alerts) == 1

    def test_normal_dns_query_no_alert(self):
        det = DnsTunnelingDetector(entropy_threshold=3.5, length_threshold=50)
        layer7 = {
            "dns": {
                "query_name": "www.google.com",
                "name_entropy": 2.8,
                "name_length": 14,
                "subdomain_depth": 2,
            }
        }
        alerts = list(det.analyze(make_meta(protocol="udp", dst_port=53), layer7, None))
        assert len(alerts) == 0

    def test_no_dns_layer7_no_alert(self):
        det = DnsTunnelingDetector()
        alerts = list(det.analyze(make_meta(), {}, None))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# HTTP attacks
# ---------------------------------------------------------------------------

class TestHttpAttackDetector:
    def test_sqli_alert(self):
        det = HttpAttackDetector()
        layer7 = {"http": {"sqli_suspect": True, "xss_suspect": False,
                           "path_traversal_suspect": False, "scanner_ua": False,
                           "uri": "/search?q=1+UNION+SELECT", "method": "GET"}}
        alerts = list(det.analyze(make_meta(dst_port=80), layer7, None))
        sqli_alerts = [a for a in alerts if "sqli" in a.tags]
        assert len(sqli_alerts) == 1
        assert sqli_alerts[0].mitre_technique == "T1190"

    def test_xss_alert(self):
        det = HttpAttackDetector()
        layer7 = {"http": {"sqli_suspect": False, "xss_suspect": True,
                           "path_traversal_suspect": False, "scanner_ua": False,
                           "uri": "/<script>alert(1)</script>", "method": "GET"}}
        alerts = list(det.analyze(make_meta(dst_port=80), layer7, None))
        xss_alerts = [a for a in alerts if "xss" in a.tags]
        assert len(xss_alerts) == 1

    def test_scanner_ua_alert(self):
        det = HttpAttackDetector()
        layer7 = {"http": {"sqli_suspect": False, "xss_suspect": False,
                           "path_traversal_suspect": False, "scanner_ua": True,
                           "user_agent": "nikto/2.1.6", "uri": "/", "method": "GET"}}
        alerts = list(det.analyze(make_meta(dst_port=80), layer7, None))
        scanner_alerts = [a for a in alerts if "scanner" in a.tags]
        assert len(scanner_alerts) == 1

    def test_no_http_no_alert(self):
        det = HttpAttackDetector()
        alerts = list(det.analyze(make_meta(), {}, None))
        assert len(alerts) == 0

    def test_clean_request_no_alert(self):
        det = HttpAttackDetector()
        layer7 = {"http": {"sqli_suspect": False, "xss_suspect": False,
                           "path_traversal_suspect": False, "scanner_ua": False}}
        alerts = list(det.analyze(make_meta(dst_port=80), layer7, None))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------

def _make_flow(byte_count: int, flow_id: str = "abc123") -> Flow:
    f = Flow(
        flow_id=flow_id,
        protocol="tcp",
        src_ip="10.0.0.1",
        src_port=54321,
        dst_ip="1.2.3.4",
        dst_port=443,
    )
    f.byte_count = byte_count
    f.packet_count = 100
    return f


class TestDataExfiltrationDetector:
    def test_large_flow_triggers(self):
        det = DataExfiltrationDetector(threshold_bytes=1024)
        flow = _make_flow(byte_count=2048)
        alerts = list(det.analyze(make_meta(), {}, flow))
        assert len(alerts) == 1
        assert "exfiltration" in alerts[0].tags
        assert alerts[0].mitre_technique == "T1041"

    def test_small_flow_no_alert(self):
        det = DataExfiltrationDetector(threshold_bytes=10 * 1024 * 1024)
        flow = _make_flow(byte_count=1000)
        alerts = list(det.analyze(make_meta(), {}, flow))
        assert len(alerts) == 0

    def test_same_flow_alerts_only_once(self):
        det = DataExfiltrationDetector(threshold_bytes=100)
        flow = _make_flow(byte_count=500, flow_id="unique-flow")
        alerts1 = list(det.analyze(make_meta(), {}, flow))
        alerts2 = list(det.analyze(make_meta(), {}, flow))
        assert len(alerts1) == 1
        assert len(alerts2) == 0  # Already alerted

    def test_no_flow_no_alert(self):
        det = DataExfiltrationDetector()
        alerts = list(det.analyze(make_meta(), {}, None))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------

class TestBeaconingDetector:
    def test_regular_beacon_triggers(self):
        det = BeaconingDetector(min_connections=6, cv_threshold=0.20)
        # Simulate regular 30-second intervals
        base_ts = 1000.0
        interval = 30.0
        alerts = []
        for i in range(10):
            meta = make_meta(
                src_ip="infected",
                dst_ip="c2-server",
                dst_port=4444,
                timestamp=base_ts + i * interval,
            )
            alerts.extend(det.analyze(meta, {}, None))

        beacon_alerts = [a for a in alerts if "beaconing" in a.tags]
        assert len(beacon_alerts) == 1
        assert beacon_alerts[0].mitre_technique == "T1071"
        assert beacon_alerts[0].evidence["coefficient_of_variation"] < 0.20

    def test_irregular_traffic_no_alert(self):
        det = BeaconingDetector(min_connections=6, cv_threshold=0.10)
        # Highly irregular intervals (human browsing pattern)
        intervals = [1.0, 5.0, 300.0, 0.5, 120.0, 0.2, 45.0, 200.0, 3.0]
        base_ts = 0.0
        ts = base_ts
        alerts = []
        for interval in intervals:
            ts += interval
            meta = make_meta(
                src_ip="user", dst_ip="website", dst_port=443, timestamp=ts
            )
            alerts.extend(det.analyze(meta, {}, None))

        beacon_alerts = [a for a in alerts if "beaconing" in a.tags]
        assert len(beacon_alerts) == 0

    def test_insufficient_samples_no_alert(self):
        det = BeaconingDetector(min_connections=10)
        ts = 1000.0
        alerts = []
        for i in range(5):  # Only 5 — below min_connections
            meta = make_meta(src_ip="host", dst_ip="target", dst_port=80, timestamp=ts + i * 30)
            alerts.extend(det.analyze(meta, {}, None))
        assert len(alerts) == 0
