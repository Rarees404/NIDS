"""Long-running daemon concerns: bounded memory, thread safety, retention, bad input."""
from __future__ import annotations

import sqlite3
import threading
import time

from pynids.alerts.manager import AlertManager
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.alerts.outputs.sqlite_out import SQLiteOutput
from pynids.detection.anomaly import AnomalyDetector, BruteForceDetector, PortScanDetector
from pynids.detection.behavioral import BeaconingDetector
from pynids.engine import DetectionEngine
from pynids.flow.tracker import FlowTracker
from pynids.intel.threat_intel import ThreatIntel
from tests.conftest import make_meta


def _alert(**kw) -> Alert:
    base = dict(alert_type=AlertType.ANOMALY, severity=Severity.MEDIUM, message="m",
                src_ip="10.0.0.1", dst_ip="10.0.0.2", rule_id="R")
    base.update(kw)
    return Alert(**base)


class TestAlertManager:
    def test_dedup_state_is_pruned(self):
        am = AlertManager(dedup_window=60)
        for i in range(500):
            am.add(_alert(dst_ip=f"10.1.{i // 250}.{i % 250}"))
        assert len(am._dedup) == 500
        am._prune(time.time() + 3600)
        assert am._dedup == {} and not am._corr_window

    def test_concurrent_adds_and_reentrant_outputs(self):
        am = AlertManager(dedup_window=0.0, correlation_threshold=2)

        class Echo:  # an output that adds an alert of its own, like C2Correlator
            def emit(self, alert):
                if alert.rule_id == "R":
                    am.add(_alert(rule_id="ECHO", src_ip=alert.src_ip))

            def close(self):
                pass

        am.register_output(Echo())
        errors = []

        def worker(n):
            try:
                for i in range(300):
                    am.add(_alert(src_ip=f"10.9.{n}.{i % 50}", rule_id="R"))
            except Exception as exc:  # pragma: no cover — the failure being tested
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors
        assert am.total_seen == 4 * 300 * 2


class TestDetectorPruning:
    def test_engine_prunes_detector_state(self):
        engine = DetectionEngine({})
        t0 = 1_000_000.0
        for i in range(200):
            engine.process_packet(make_meta(src_ip=f"203.0.113.{i}", dst_ip="10.0.0.2",
                                            dst_port=22, tcp_flags=0x02, timestamp=t0))
        scan = next(d for d in engine._detectors if isinstance(d, PortScanDetector))
        bf = next(d for d in engine._detectors if isinstance(d, BruteForceDetector))
        vol = next(d for d in engine._detectors if isinstance(d, AnomalyDetector))
        assert len(scan._state) == 200 and len(bf._attempts) == 200
        # One packet two hours later triggers the per-minute prune.
        engine.process_packet(make_meta(timestamp=t0 + 7200))
        assert len(scan._state) <= 1 and len(bf._attempts) == 0 and len(vol._per_source) <= 1

    def test_beaconing_keeps_active_pairs(self):
        det = BeaconingDetector()
        det._history[("a", "b", 1)].append(1000.0)
        det._history[("a", "c", 1)].append(5000.0)
        det.prune(5000.0 + 60)
        assert list(det._history) == [("a", "c", 1)]


class TestFlowTracker:
    def test_max_flows_enforced_between_gc_passes(self):
        tracker = FlowTracker(max_flows=100)
        for i in range(1000):
            tracker.update(make_meta(src_port=10000 + i))
        assert tracker.active_count <= 100

    def test_replayed_old_traffic_is_not_expired_by_wall_clock(self):
        tracker = FlowTracker(idle_timeout=300)
        old = 1_000_000.0  # 1970: a PCAP from long ago
        tracker.update(make_meta(timestamp=old))
        tracker._last_gc = 0  # force a GC pass on the next packet
        tracker.update(make_meta(src_port=2, timestamp=old + 1))
        assert tracker.active_count == 2


class TestThreatIntel:
    def test_lowercase_severity_does_not_break_the_engine(self):
        intel = ThreatIntel()
        intel.add_network("198.51.100.0/24", "c2", "high", "test")
        intel.add_domain("evil.test", "malware", "Critical", "test")
        intel.add_domain("odd.test", "malware", "bogus", "test")
        engine = DetectionEngine({}, intel=intel)
        alerts = engine.process_packet(make_meta(dst_ip="198.51.100.7"))
        assert any(a.severity == Severity.HIGH and a.alert_type == AlertType.THREAT_INTEL for a in alerts)
        assert intel.check_domain("evil.test").severity == "CRITICAL"
        assert intel.check_domain("odd.test").severity == "MEDIUM"


class TestRetention:
    def test_prune_deletes_old_alerts_and_keeps_search_index_in_sync(self, tmp_path):
        path = tmp_path / "events.db"
        store = SQLiteOutput(str(path), batch_size=0)
        store.emit(_alert(message="ancient tunnel", timestamp=time.time() - 90 * 86400))
        store.emit(_alert(message="fresh tunnel"))
        assert store.prune(30) == 1
        assert store.prune(0) == 0
        conn = sqlite3.connect(str(path))
        rows = conn.execute("SELECT a.message FROM alerts_fts f JOIN alerts a ON a.rowid = f.rowid "
                            "WHERE alerts_fts MATCH 'tunnel'").fetchall()
        assert rows == [("fresh tunnel",)]
        assert conn.execute("INSERT INTO alerts_fts(alerts_fts) VALUES('integrity-check')") is not None
        conn.close()
        store.close()
