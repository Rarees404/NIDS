"""End-to-end tests for the DetectionEngine pipeline."""
from __future__ import annotations

import pytest
from typing import List
from unittest.mock import MagicMock

from pynids.engine import DetectionEngine
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.alerts.manager import AlertManager
from tests.conftest import AlertCollector, make_meta


def _build_engine(
    rules: list | None = None,
    config: dict | None = None,
    intel=None,
) -> tuple[DetectionEngine, AlertCollector]:
    """Helper: build an engine backed by an AlertCollector for easy inspection."""
    collector = AlertCollector()
    mgr = AlertManager(dedup_window=0, correlation_window=300, correlation_threshold=3)
    mgr.register_output(collector)

    cfg = config or {}

    if rules is not None:
        # Write rules to a temp file
        import tempfile, yaml, os
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.dump({"rules": rules}, f)
        f.close()
        engine = DetectionEngine(config=cfg, rules_path=f.name, intel=intel, alert_manager=mgr)
        os.unlink(f.name)
    else:
        engine = DetectionEngine(config=cfg, rules_path=None, intel=intel, alert_manager=mgr)

    return engine, collector


class TestEngineSignaturePipeline:
    def test_signature_alert_generated(self):
        rules = [
            {
                "id": "SSH-PROBE",
                "description": "SSH port hit",
                "severity": "HIGH",
                "match": {"field": "dst_port", "op": "eq", "value": 22},
            }
        ]
        engine, collector = _build_engine(rules=rules)
        engine.process_packet(make_meta(dst_port=22, protocol="tcp"))
        sig_alerts = collector.of_type(AlertType.SIGNATURE)
        assert len(sig_alerts) >= 1
        assert sig_alerts[0].rule_id == "SSH-PROBE"

    def test_no_alert_for_non_matching_packet(self):
        rules = [
            {"id": "X", "description": "x", "severity": "LOW",
             "match": {"field": "dst_port", "op": "eq", "value": 9999}}
        ]
        engine, collector = _build_engine(rules=rules)
        engine.process_packet(make_meta(dst_port=80))
        assert collector.count == 0


class TestEngineAnomalyPipeline:
    def test_brute_force_detected(self):
        config = {"brute_force": {"threshold": 5, "window": 60, "ports": [22]}}
        engine, collector = _build_engine(config=config)
        for i in range(10):
            engine.process_packet(
                make_meta(src_ip="attacker", dst_ip="server", dst_port=22, timestamp=float(i))
            )
        bf_alerts = [a for a in collector.alerts if "brute_force" in (a.tags or [])]
        assert len(bf_alerts) >= 1


class TestEngineBehavioralPipeline:
    def test_http_sqli_detected(self):
        engine, collector = _build_engine()
        # Send an HTTP packet that will trigger the HTTP dissector
        sqli_payload = (
            b"GET /page?id=1+UNION+SELECT+*+FROM+users HTTP/1.1\r\n"
            b"Host: target.com\r\n\r\n"
        )
        engine.process_packet(make_meta(dst_port=80, protocol="tcp", payload=sqli_payload))
        sqli_alerts = [a for a in collector.alerts if "sqli" in (a.tags or [])]
        assert len(sqli_alerts) >= 1

    def test_dns_tunneling_detected(self):
        engine, collector = _build_engine(
            config={"behavioral": {"dns_entropy_threshold": 3.0, "dns_length_threshold": 30}}
        )

        # Craft a DNS-looking packet with known high-entropy query
        # (We inject synthetic layer7 by using a query name with high entropy)
        # The behavioral detector reads layer7.dns — we test via dissector's output.
        # Build a minimal DNS packet for a high-entropy name
        from pynids.protocols.dissector import _entropy
        name = "aB3xZ9qR7yN2wK5vL1mJ8cF4eD6hG0pT"
        assert _entropy(name.encode()) > 3.0

        # We can't easily craft raw DNS bytes here, so call the engine
        # directly with a mock that the dissector will produce a dns result.
        # Instead, test the behavioral detector directly.
        from pynids.detection.behavioral import DnsTunnelingDetector
        det = DnsTunnelingDetector(entropy_threshold=3.0, length_threshold=20)
        layer7 = {"dns": {"query_name": name, "name_entropy": _entropy(name.encode()),
                           "name_length": len(name), "subdomain_depth": 2}}
        meta = make_meta(dst_port=53, protocol="udp")
        alerts = list(det.analyze(meta, layer7, None))
        assert len(alerts) == 1


class TestEngineThreatIntel:
    def test_threat_intel_ip_match(self):
        from pynids.intel.threat_intel import ThreatIntel
        import tempfile, yaml, os

        bad_ips = {"entries": [
            {"cidr": "10.66.66.0/24", "category": "c2", "severity": "HIGH",
             "description": "test malicious range"}
        ]}
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.dump(bad_ips, f)
        f.close()

        intel = ThreatIntel(bad_ips_path=f.name)
        os.unlink(f.name)

        engine, collector = _build_engine(intel=intel)
        engine.process_packet(make_meta(src_ip="10.66.66.5", dst_ip="1.2.3.4"))

        ti_alerts = collector.of_type(AlertType.THREAT_INTEL)
        assert len(ti_alerts) >= 1
        assert ti_alerts[0].severity == Severity.HIGH


class TestEngineStats:
    def test_stats_increment(self):
        engine, _ = _build_engine()
        for _ in range(10):
            engine.process_packet(make_meta())
        stats = engine.stats
        assert stats["packets_processed"] == 10
        assert stats["packets_per_second"] > 0

    def test_flow_count_increments(self):
        engine, _ = _build_engine()
        engine.process_packet(make_meta(src_ip="A", dst_ip="B", dst_port=80))
        engine.process_packet(make_meta(src_ip="C", dst_ip="D", dst_port=443))
        assert engine.stats["active_flows"] == 2


class TestEngineHotReload:
    def test_reload_rules_no_path(self):
        engine, _ = _build_engine()
        assert engine.reload_rules() is False

    def test_reload_detects_unchanged_file(self):
        import tempfile, yaml, os
        rules = [{"id": "R1", "description": "x", "severity": "LOW",
                  "match": {"field": "dst_port", "op": "eq", "value": 9999}}]
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        yaml.dump({"rules": rules}, f)
        f.close()

        mgr = AlertManager(dedup_window=0)
        engine = DetectionEngine(config={}, rules_path=f.name, alert_manager=mgr)
        # File unchanged → returns False
        assert engine.reload_rules() is False
        os.unlink(f.name)
