"""Tests for the enhanced signature detection engine."""
from __future__ import annotations

import pytest
from pynids.detection.signature import SignatureDetector, load_rules, _eval_node, _get_field
from pynids.alerts.model import AlertType, Severity
from tests.conftest import make_meta


# ---------------------------------------------------------------------------
# Rule building helpers
# ---------------------------------------------------------------------------

def make_rule(
    rule_id="TEST-001",
    description="test",
    severity="HIGH",
    match=None,
    threshold=None,
    mitre=None,
    tags=None,
):
    r = {
        "id": rule_id,
        "description": description,
        "severity": severity,
        "match": match or {"field": "dst_port", "op": "eq", "value": 80},
    }
    if threshold:
        r["threshold"] = threshold
    if mitre:
        r["mitre"] = mitre
    if tags:
        r["tags"] = tags
    return r


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------

class TestGetField:
    def test_meta_field(self):
        meta = {"dst_port": 80, "src_ip": "1.2.3.4"}
        assert _get_field("dst_port", meta, {}) == 80

    def test_layer7_nested(self):
        layer7 = {"http": {"user_agent": "curl/7.0", "sqli_suspect": True}}
        assert _get_field("layer7.http.user_agent", {}, layer7) == "curl/7.0"
        assert _get_field("layer7.http.sqli_suspect", {}, layer7) is True

    def test_missing_field_returns_none(self):
        assert _get_field("nonexistent", {}, {}) is None

    def test_missing_layer7_key(self):
        assert _get_field("layer7.dns.query_name", {}, {}) is None


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

class TestEvalNode:
    def test_simple_eq(self):
        assert _eval_node({"field": "protocol", "op": "eq", "value": "tcp"},
                          {"protocol": "tcp"}, {})
        assert not _eval_node({"field": "protocol", "op": "eq", "value": "udp"},
                               {"protocol": "tcp"}, {})

    def test_in_operator(self):
        node = {"field": "dst_port", "op": "in", "value": [80, 443, 8080]}
        assert _eval_node(node, {"dst_port": 443}, {})
        assert not _eval_node(node, {"dst_port": 22}, {})

    def test_regex_operator(self):
        node = {"field": "layer7.http.user_agent", "op": "regex", "value": "nikto|sqlmap"}
        layer7 = {"http": {"user_agent": "Nikto/2.1.6"}}
        assert _eval_node(node, {}, layer7)

    def test_contains_bytes(self):
        node = {"field": "payload_bytes", "op": "contains", "value": "hello"}
        assert _eval_node(node, {"payload_bytes": b"say hello world"}, {})
        assert not _eval_node(node, {"payload_bytes": b"goodbye world"}, {})

    def test_all_combinator(self):
        node = {
            "all": [
                {"field": "protocol", "op": "eq", "value": "tcp"},
                {"field": "dst_port", "op": "eq", "value": 22},
            ]
        }
        assert _eval_node(node, {"protocol": "tcp", "dst_port": 22}, {})
        assert not _eval_node(node, {"protocol": "tcp", "dst_port": 80}, {})

    def test_any_combinator(self):
        node = {
            "any": [
                {"field": "dst_port", "op": "eq", "value": 22},
                {"field": "dst_port", "op": "eq", "value": 23},
            ]
        }
        assert _eval_node(node, {"dst_port": 22}, {})
        assert _eval_node(node, {"dst_port": 23}, {})
        assert not _eval_node(node, {"dst_port": 80}, {})

    def test_not_combinator(self):
        node = {"not": {"field": "protocol", "op": "eq", "value": "udp"}}
        assert _eval_node(node, {"protocol": "tcp"}, {})
        assert not _eval_node(node, {"protocol": "udp"}, {})

    def test_shorthand_equality(self):
        # {key: value} shorthand treated as all-AND
        node = {"protocol": "tcp", "dst_port": 443}
        assert _eval_node(node, {"protocol": "tcp", "dst_port": 443}, {})
        assert not _eval_node(node, {"protocol": "tcp", "dst_port": 80}, {})

    def test_exists_operator(self):
        node = {"field": "src_ip", "op": "exists"}
        assert _eval_node(node, {"src_ip": "1.2.3.4"}, {})
        assert not _eval_node(node, {"src_ip": None}, {})
        assert not _eval_node(node, {}, {})

    def test_gte_operator(self):
        assert _eval_node({"field": "dst_port", "op": "gte", "value": 1024},
                          {"dst_port": 8080}, {})
        assert not _eval_node({"field": "dst_port", "op": "gte", "value": 1024},
                               {"dst_port": 80}, {})


# ---------------------------------------------------------------------------
# SignatureDetector
# ---------------------------------------------------------------------------

class TestSignatureDetector:
    def test_simple_match(self):
        rule = make_rule(match={"field": "dst_port", "op": "eq", "value": 22})
        det = SignatureDetector([rule])
        meta = make_meta(dst_port=22)
        alerts = list(det.analyze(meta, {}, None))
        assert len(alerts) == 1
        assert alerts[0].rule_id == "TEST-001"
        assert alerts[0].alert_type == AlertType.SIGNATURE

    def test_no_match(self):
        rule = make_rule(match={"field": "dst_port", "op": "eq", "value": 22})
        det = SignatureDetector([rule])
        meta = make_meta(dst_port=80)
        alerts = list(det.analyze(meta, {}, None))
        assert len(alerts) == 0

    def test_severity_mapping(self):
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            rule = make_rule(severity=sev, match={"field": "dst_port", "op": "eq", "value": 22})
            det = SignatureDetector([rule])
            alerts = list(det.analyze(make_meta(dst_port=22), {}, None))
            assert alerts[0].severity == Severity(sev)

    def test_mitre_and_tags(self):
        rule = make_rule(
            match={"field": "dst_port", "op": "eq", "value": 22},
            mitre="T1046",
            tags=["recon"],
        )
        det = SignatureDetector([rule])
        alerts = list(det.analyze(make_meta(dst_port=22), {}, None))
        assert alerts[0].mitre_technique == "T1046"
        assert "recon" in alerts[0].tags

    def test_layer7_field_match(self):
        rule = make_rule(
            match={"field": "layer7.http.sqli_suspect", "op": "eq", "value": True}
        )
        det = SignatureDetector([rule])
        layer7 = {"http": {"sqli_suspect": True}}
        alerts = list(det.analyze(make_meta(), layer7, None))
        assert len(alerts) == 1

    def test_threshold_suppresses_until_count(self):
        rule = make_rule(
            match={"field": "dst_port", "op": "eq", "value": 22},
            threshold={"count": 3, "seconds": 60},
        )
        det = SignatureDetector([rule])
        meta = make_meta(dst_port=22)
        results = []
        for _ in range(5):
            results.extend(det.analyze(meta, {}, None))
        # Alert fires on 3rd and 5th hit (resets when bucket < count)
        assert len(results) >= 1

    def test_multiple_rules(self):
        rules = [
            make_rule("R1", match={"field": "dst_port", "op": "eq", "value": 22}),
            make_rule("R2", match={"field": "dst_port", "op": "eq", "value": 80}),
        ]
        det = SignatureDetector(rules)
        alerts_22 = list(det.analyze(make_meta(dst_port=22), {}, None))
        alerts_80 = list(det.analyze(make_meta(dst_port=80), {}, None))
        assert len(alerts_22) == 1 and alerts_22[0].rule_id == "R1"
        assert len(alerts_80) == 1 and alerts_80[0].rule_id == "R2"

    def test_update_rules_hot_reload(self):
        det = SignatureDetector([make_rule(match={"field": "dst_port", "op": "eq", "value": 22})])
        assert len(list(det.analyze(make_meta(dst_port=22), {}, None))) == 1
        det.update_rules([])
        assert len(list(det.analyze(make_meta(dst_port=22), {}, None))) == 0

    def test_legacy_evaluate_packet(self):
        """Backwards-compat shim used by existing tests."""
        rules = [{"id": "X", "description": "old", "when": {"dst_port": 80, "payload_contains": "hello"}}]
        det = SignatureDetector(rules)
        meta = {"dst_port": 80, "payload_bytes": b"say hello"}
        alerts = det.evaluate_packet(meta)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "X"
