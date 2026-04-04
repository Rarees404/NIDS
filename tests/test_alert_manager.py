"""Tests for AlertManager: deduplication, suppression, and correlation."""
from __future__ import annotations

import time
import pytest
from pynids.alerts.manager import AlertManager, BaseOutput
from pynids.alerts.model import Alert, AlertType, Severity
from tests.conftest import AlertCollector


def make_alert(
    rule_id: str = "R1",
    src_ip: str = "1.2.3.4",
    dst_ip: str = "5.6.7.8",
    dst_port: int = 80,
    severity: Severity = Severity.MEDIUM,
    alert_type: AlertType = AlertType.SIGNATURE,
) -> Alert:
    return Alert(
        alert_type=alert_type,
        severity=severity,
        message="test alert",
        rule_id=rule_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_duplicate_within_window_suppressed(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=60.0)
        mgr.register_output(collector)

        a = make_alert()
        mgr.add(a)
        mgr.add(make_alert())  # Same dedup key
        assert collector.count == 1
        assert mgr.stats["total_deduplicated"] == 1

    def test_different_rules_not_deduplicated(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=60.0)
        mgr.register_output(collector)
        mgr.add(make_alert(rule_id="R1"))
        mgr.add(make_alert(rule_id="R2"))
        assert collector.count == 2

    def test_zero_window_disables_dedup(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=0)
        mgr.register_output(collector)
        mgr.add(make_alert())
        mgr.add(make_alert())
        assert collector.count == 2


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

class TestSuppression:
    def test_exact_ip_suppressed(self):
        collector = AlertCollector()
        mgr = AlertManager(
            dedup_window=0,
            suppression_rules=[{"rule_id": "*", "src_cidr": "1.2.3.4/32"}],
        )
        mgr.register_output(collector)
        mgr.add(make_alert(src_ip="1.2.3.4"))
        assert collector.count == 0
        assert mgr.stats["total_suppressed"] == 1

    def test_cidr_range_suppressed(self):
        collector = AlertCollector()
        mgr = AlertManager(
            dedup_window=0,
            suppression_rules=[{"rule_id": "R1", "src_cidr": "10.0.0.0/8"}],
        )
        mgr.register_output(collector)
        mgr.add(make_alert(rule_id="R1", src_ip="10.5.6.7"))
        assert collector.count == 0

    def test_different_rule_not_suppressed(self):
        collector = AlertCollector()
        mgr = AlertManager(
            dedup_window=0,
            suppression_rules=[{"rule_id": "R1", "src_cidr": "10.0.0.0/8"}],
        )
        mgr.register_output(collector)
        mgr.add(make_alert(rule_id="R2", src_ip="10.5.6.7"))
        assert collector.count == 1

    def test_outside_cidr_not_suppressed(self):
        collector = AlertCollector()
        mgr = AlertManager(
            dedup_window=0,
            suppression_rules=[{"rule_id": "*", "src_cidr": "192.168.0.0/16"}],
        )
        mgr.register_output(collector)
        mgr.add(make_alert(src_ip="10.0.0.1"))
        assert collector.count == 1


# ---------------------------------------------------------------------------
# Severity gate
# ---------------------------------------------------------------------------

class TestSeverityGate:
    def test_low_filtered_when_min_is_high(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=0, min_severity=Severity.HIGH)
        mgr.register_output(collector)
        mgr.add(make_alert(severity=Severity.LOW))
        mgr.add(make_alert(severity=Severity.MEDIUM))
        assert collector.count == 0

    def test_high_passes_when_min_is_high(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=0, min_severity=Severity.HIGH)
        mgr.register_output(collector)
        mgr.add(make_alert(severity=Severity.HIGH))
        mgr.add(make_alert(severity=Severity.CRITICAL))
        assert collector.count == 2


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

class TestCorrelation:
    def test_multi_rule_correlation(self):
        collector = AlertCollector()
        mgr = AlertManager(
            dedup_window=0,
            correlation_window=300,
            correlation_threshold=3,
        )
        mgr.register_output(collector)

        src = "attacker"
        for rule_id in ("R1", "R2", "R3", "R4"):
            mgr.add(make_alert(rule_id=rule_id, src_ip=src))

        corr = [a for a in collector.alerts if a.alert_type == AlertType.CORRELATION]
        assert len(corr) >= 1
        assert corr[0].src_ip == src
        assert corr[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_tracking(self):
        collector = AlertCollector()
        mgr = AlertManager(dedup_window=60)
        mgr.register_output(collector)

        mgr.add(make_alert(rule_id="R1"))
        mgr.add(make_alert(rule_id="R1"))  # dedup'd

        stats = mgr.stats
        assert stats["total_seen"] == 2
        assert stats["total_deduplicated"] == 1
        assert stats["total_emitted"] == 1
