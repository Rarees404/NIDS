"""Tests for anomaly, port-scan, and brute-force detectors."""
from __future__ import annotations

import time
import pytest
from pynids.detection.anomaly import AnomalyDetector, PortScanDetector, BruteForceDetector
from pynids.alerts.model import AlertType
from tests.conftest import make_meta


class TestAnomalyDetector:
    def test_no_alert_on_steady_traffic(self):
        det = AnomalyDetector(ewma_alpha=0.3, sigma_threshold=2.0, window_seconds=10)
        meta = make_meta(src_ip="1.2.3.4", timestamp=100.0)
        # Feed 5 packets in the same window — not enough history to trigger
        alerts = []
        for i in range(5):
            alerts.extend(det.analyze(meta, {}, None))
        assert len(alerts) == 0

    def test_spike_triggers_alert(self):
        det = AnomalyDetector(ewma_alpha=0.3, sigma_threshold=2.0, window_seconds=10)
        src = "1.2.3.4"

        # Establish baseline: low rate across many windows
        base_ts = 0.0
        for w in range(20):
            for _ in range(2):  # 2 packets per window
                meta = make_meta(src_ip=src, timestamp=base_ts + w * 10.0 + 0.5)
                list(det.analyze(meta, {}, None))

        # Spike: 100 packets in the next window
        spike_ts = base_ts + 20 * 10.0
        alerts = []
        for _ in range(100):
            meta = make_meta(src_ip=src, timestamp=spike_ts + 0.1)
            alerts.extend(det.analyze(meta, {}, None))

        assert any(a.alert_type == AlertType.ANOMALY for a in alerts)

    def test_ignores_packet_without_src_ip(self):
        det = AnomalyDetector()
        meta = make_meta()
        meta["src_ip"] = None
        alerts = list(det.analyze(meta, {}, None))
        assert len(alerts) == 0


class TestPortScanDetector:
    def test_horizontal_scan_alert(self):
        det = PortScanDetector(horizontal_threshold=5, horizontal_window=60)
        ts = time.time()
        alerts = []
        # Same source, same port, different destinations
        for i in range(10):
            meta = make_meta(
                src_ip="attacker",
                dst_ip=f"192.168.1.{i}",
                dst_port=80,
                timestamp=ts + i * 0.1,
            )
            alerts.extend(det.analyze(meta, {}, None))

        horiz_alerts = [a for a in alerts if "host_sweep" in a.tags]
        assert len(horiz_alerts) == 1
        assert horiz_alerts[0].mitre_technique == "T1046"

    def test_vertical_scan_alert(self):
        det = PortScanDetector(vertical_threshold=5, vertical_window=60)
        ts = time.time()
        alerts = []
        # Same source, same destination, different ports
        for port in range(20, 30):
            meta = make_meta(
                src_ip="attacker",
                dst_ip="target",
                dst_port=port,
                timestamp=ts,
            )
            alerts.extend(det.analyze(meta, {}, None))

        vert_alerts = [a for a in alerts if "vertical_scan" in a.tags]
        assert len(vert_alerts) == 1

    def test_no_alert_below_threshold(self):
        det = PortScanDetector(horizontal_threshold=20, vertical_threshold=15)
        ts = time.time()
        alerts = []
        for i in range(3):  # Only 3 — below thresholds
            meta = make_meta(src_ip="attacker", dst_ip=f"10.0.0.{i}", dst_port=22, timestamp=ts)
            alerts.extend(det.analyze(meta, {}, None))
        assert len(alerts) == 0

    def test_no_alert_missing_fields(self):
        det = PortScanDetector()
        meta = {"src_ip": "1.2.3.4", "protocol": "tcp"}  # no dst_ip or dst_port
        alerts = list(det.analyze(meta, {}, None))
        assert len(alerts) == 0


class TestBruteForceDetector:
    def test_brute_force_alert(self):
        det = BruteForceDetector(threshold=5, window=30.0)
        ts = time.time()
        alerts = []
        for i in range(10):
            meta = make_meta(src_ip="attacker", dst_ip="server", dst_port=22, timestamp=ts + i * 0.5)
            alerts.extend(det.analyze(meta, {}, None))

        bf_alerts = [a for a in alerts if "brute_force" in a.tags]
        assert len(bf_alerts) == 1
        assert bf_alerts[0].mitre_technique == "T1110"

    def test_only_watched_ports_trigger(self):
        det = BruteForceDetector(threshold=5, window=30.0, watched_ports=frozenset({22}))
        ts = time.time()
        alerts = []
        for i in range(10):
            # Port 80 is not in watched_ports
            meta = make_meta(src_ip="attacker", dst_ip="server", dst_port=80, timestamp=ts + i)
            alerts.extend(det.analyze(meta, {}, None))
        assert len(alerts) == 0

    def test_no_alert_below_threshold(self):
        det = BruteForceDetector(threshold=10, window=30.0)
        ts = time.time()
        alerts = []
        for i in range(5):
            meta = make_meta(src_ip="attacker", dst_ip="server", dst_port=22, timestamp=ts + i)
            alerts.extend(det.analyze(meta, {}, None))
        assert len(alerts) == 0
