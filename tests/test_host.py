"""Host inspection: signatures, persistence, sockets, IP dossiers, LAN, host-aware detectors, allowlist, investigation."""
from __future__ import annotations

import json
import plistlib
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from pynids.ai import investigate as inv
from pynids.alerts.allowlist import Allowlist
from pynids.alerts.classify import classify
from pynids.alerts.guide import describe
from pynids.alerts.manager import AlertManager
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.detection.hostrisk import (
    BaselineDetector, BaselineStore, C2Correlator, ProcessRiskDetector,
)
from pynids.host import codesign, connections, dossier, lan
from pynids.host.inspector import HostInspector
from pynids.host.persistence import PersistenceIndex, scan
from pynids.service.api import ServiceContext, make_server
from pynids.service.live import LiveState
from tests.conftest import AlertCollector, make_meta

DEV_ID = """Executable=/Applications/Slack.app/Contents/MacOS/Slack
Identifier=com.tinyspeck.slackmacgap
CodeDirectory v=20500 size=765 flags=0x10000(runtime) hashes=13+7 location=embedded
Authority=Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=BQR82RBBHL
"""
ADHOC = """Executable=/tmp/x
Identifier=x
CodeDirectory v=20400 size=250 flags=0x20002(adhoc,linker-signed) hashes=5+0 location=embedded
Signature=adhoc
TeamIdentifier=not set
"""
APPLE = """Identifier=com.apple.curl
CodeDirectory v=20400 size=679 flags=0x0(none) hashes=16+2 location=embedded
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
TeamIdentifier=not set
"""


# ---------------------------------------------------------------------------
# Code signatures
# ---------------------------------------------------------------------------

class TestCodesign:
    def test_parse(self):
        sig = codesign.parse_codesign(DEV_ID, 0)
        assert sig["status"] == "developer_id" and sig["team_id"] == "BQR82RBBHL"
        assert sig["hardened_runtime"] is True
        assert codesign.parse_codesign(ADHOC, 0)["status"] == "adhoc"
        assert codesign.parse_codesign(APPLE, 0)["status"] == "apple"
        assert codesign.parse_codesign("/x: code object is not signed at all", 1)["status"] == "unsigned"

    @pytest.mark.parametrize("exe,flagged", [
        ("/tmp/update", True),
        ("/private/var/folders/xy/T/payload", True),
        ("/private/var/folders/xy/T/AppTranslocation/ABC/d/Foo.app/Contents/MacOS/Foo", False),
        ("/Users/Shared/.hidden/agent", True),
        ("/Users/me/Library/Application Support/com.helper/helper", True),
        ("/Users/me/Library/Application Support/JetBrains/Toolbox/Toolbox.app/Contents/MacOS/x", False),
        ("/Users/me/.venv/bin/python3", False),
        ("/opt/homebrew/bin/node", False),
        ("/Applications/Slack.app/Contents/MacOS/Slack", False),
    ])
    def test_path_risk(self, exe, flagged):
        assert bool(codesign.path_risk(exe)) is flagged

    def test_assess(self):
        bad = codesign.assess("/tmp/x", {"status": "unsigned"})
        assert bad["risk"] == 3 and {"odd_path", "unsigned"} <= set(bad["flags"])
        brew = codesign.assess("/opt/homebrew/bin/node", {"status": "adhoc"})
        assert brew["risk"] == 0
        signed_odd = codesign.assess("/tmp/Installer", {"status": "developer_id"})
        assert signed_odd["risk"] == 1
        tampered = codesign.assess("/Applications/X.app/Contents/MacOS/X", {"status": "invalid"})
        assert tampered["risk"] == 3

    def test_checker_is_async_and_cached(self, tmp_path):
        exe = tmp_path / "bin"
        exe.write_bytes(b"x")
        calls = []
        checker = SimpleNamespace()
        checker = codesign.SignatureChecker(runner=lambda p: calls.append(p) or {"status": "unsigned"})
        assert checker.lookup(str(exe)) is None  # queued, not blocking
        checker.start()
        for _ in range(50):
            if checker.lookup(str(exe)):
                break
            time.sleep(0.02)
        assert checker.lookup(str(exe))["status"] == "unsigned"
        assert checker.check(str(exe))["label"] == "Unsigned"
        assert calls == [str(exe)]
        checker.stop()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_persistence_scan_and_index(tmp_path):
    folder = tmp_path / "LaunchAgents"
    folder.mkdir()
    with open(folder / "com.evil.agent.plist", "wb") as f:
        plistlib.dump({"Label": "com.evil.agent", "ProgramArguments": ["/Users/Shared/.x/agent", "-q"],
                       "RunAtLoad": True, "StartInterval": 60}, f)
    with open(folder / "com.vendor.helper.plist", "wb") as f:
        plistlib.dump({"Label": "com.vendor.helper", "Program": "/Applications/V.app/Contents/Helpers/h"}, f)
    (folder / "broken.plist").write_text("not a plist")
    jobs = scan(folders=[(str(folder), "agent", "test")])
    assert {j["label"] for j in jobs} == {"com.evil.agent", "com.vendor.helper"}
    evil = next(j for j in jobs if j["label"] == "com.evil.agent")
    assert evil["run_at_load"] and evil["interval"] == 60 and evil["arguments"] == ["-q"]
    index = PersistenceIndex(scanner=lambda: jobs)
    assert index.for_program("/Users/Shared/.x/agent")[0]["label"] == "com.evil.agent"
    # A helper launched from the same app bundle maps back to the app.
    assert index.for_program("/Applications/V.app/Contents/MacOS/V")[0]["label"] == "com.vendor.helper"


# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------

class TestConnections:
    def test_parse_nettop_full(self):
        out = ("com.apple.WebKit.Networking.933,4521,\n"
               "quic4 10.0.0.5:52800<->157.240.253.60:443,49,\n"
               "tcp6 fe80::1%en0.51750<->*.*,,\n")
        rows = connections.parse_nettop_full(out)
        assert rows[0]["remote_ip"] == "157.240.253.60" and rows[0]["remote_port"] == 443
        assert rows[0]["proto"] == "udp" and rows[0]["transport"] == "quic" and rows[0]["pid"] == 933
        assert rows[1]["local_ip"] == "fe80::1" and rows[1]["remote_ip"] is None

    def test_listener_rules(self):
        assert connections.is_listener({"state": "LISTEN"})
        assert connections.is_listener({"proto": "udp", "source": "socket", "local_port": 5353})
        # An outgoing UDP socket on an ephemeral port is not a service.
        assert not connections.is_listener({"proto": "udp", "source": "socket", "local_port": 61000})
        assert connections.exposure("127.0.0.1") == "this_mac"
        assert connections.exposure("::") == "all_networks"
        assert connections.exposure("192.168.1.4") == "lan"


def fake_snapshot():
    return [
        {"proto": "tcp", "local_ip": "10.0.0.2", "local_port": 50001, "remote_ip": "93.184.215.9",
         "remote_port": 443, "state": "ESTABLISHED", "pid": 7, "process": "agent", "app": "agent",
         "exe": "/tmp/agent", "listening": False, "source": "socket"},
        {"proto": "tcp", "local_ip": "0.0.0.0", "local_port": 3000, "remote_ip": None, "remote_port": None,
         "state": "LISTEN", "pid": 8, "process": "node", "app": "node", "exe": "/opt/homebrew/bin/node",
         "listening": True, "source": "socket"},
        {"proto": "tcp", "local_ip": "::", "local_port": 3000, "remote_ip": None, "remote_port": None,
         "state": "LISTEN", "pid": 8, "process": "node", "app": "node", "exe": "/opt/homebrew/bin/node",
         "listening": True, "source": "socket"},
        {"proto": "tcp", "local_ip": "127.0.0.1", "local_port": 50002, "remote_ip": "127.0.0.1",
         "remote_port": 8787, "state": "ESTABLISHED", "pid": 9, "app": "curl", "exe": "/usr/bin/curl",
         "listening": False, "source": "socket"},
    ]


def make_inspector(tmp_path, **kw):
    sigs = codesign.SignatureChecker(runner=lambda p: {"status": "unsigned" if p.startswith("/tmp") else "adhoc"})
    for exe in ("/tmp/agent", "/opt/homebrew/bin/node"):
        sigs._store(exe, sigs._runner(exe))
    live = kw.pop("live", LiveState())
    return HostInspector(live=live, signatures=sigs, snapshot=fake_snapshot,
                         persistence=PersistenceIndex(scanner=lambda: []), db_path=tmp_path / "e.db", **kw)


class TestInspector:
    def test_connections_join(self, tmp_path):
        live = LiveState()
        live.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.MEDIUM, message="beacon",
                        dst_ip="93.184.215.9", tags=["beaconing"], context={"remote_ip": "93.184.215.9"}))
        snap = make_inspector(tmp_path, live=live).connections()
        assert len(snap["connections"]) == 1  # loopback hidden by default
        conn = snap["connections"][0]
        assert conn["risk"] == 3 and {"unsigned", "odd_path", "beacon"} <= set(conn["flags"])
        # 0.0.0.0 and :: copies of one service collapse into a single row.
        assert len(snap["listening"]) == 1
        node = snap["listening"][0]
        assert node["exposure"] == "all_networks" and "exposed" in node["flags"]
        assert set(node["addresses"]) == {"0.0.0.0", "::"}
        assert snap["programs"][0]["exe"] == "/tmp/agent"
        assert snap["summary"]["flagged_programs"] == 1 and snap["summary"]["exposed_ports"] == 1

    def test_dossier_local_only_by_default(self, tmp_path):
        fetched = []
        lookups = dossier.IpLookup(fetch=lambda url, t: fetched.append(url) or {}, ptr=lambda ip: None,
                                   mode="manual")
        insp = make_inspector(tmp_path, lookups=lookups)
        d = insp.dossier("93.184.215.9")
        assert d["external"]["pending"] and not fetched
        assert d["local"]["connected_now"][0]["app"] == "agent"
        with pytest.raises(ValueError):
            insp.dossier("not-an-ip")


# ---------------------------------------------------------------------------
# IP dossier
# ---------------------------------------------------------------------------

RDAP = {
    "name": "EXAMPLE-NET", "handle": "NET-203-0-113-0-1", "country": "US",
    "startAddress": "93.184.215.0", "endAddress": "93.184.215.255",
    "cidr0_cidrs": [{"v4prefix": "93.184.215.0", "length": 24}],
    "events": [{"eventAction": "registration", "eventDate": "2001-02-03T00:00:00Z"}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Hosting LLC"]]],
         "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]]}]},
    ],
}


class TestDossier:
    def test_parsers(self):
        r = dossier.parse_rdap(RDAP)
        assert r["owner"] == "Example Hosting LLC" and r["abuse_email"] == "abuse@example.net"
        assert r["cidr"] == "93.184.215.0/24" and r["registered"] == "2001-02-03"
        idb = dossier.parse_internetdb({"ports": [22, 443], "tags": ["c2"], "vulns": ["CVE-1"], "hostnames": []})
        assert idb["listed"] and idb["tags"] == ["c2"]
        assert dossier.parse_internetdb({"detail": "No information available"}) == {"listed": False}

    def test_lookup_cache_and_privacy(self, tmp_path):
        urls = []

        def fetch(url, timeout):
            urls.append(url)
            return RDAP if "rdap" in url else {"ports": [80], "tags": []}

        lk = dossier.IpLookup(db_path=tmp_path / "e.db", fetch=fetch, ptr=lambda ip: "host.example.net")
        assert lk.lookup("192.168.1.10")["external"] is False and not urls
        first = lk.lookup("93.184.215.9")
        assert first["cached"] is False and first["ptr"] == "host.example.net"
        assert first["rdap"]["owner"] == "Example Hosting LLC" and first["internetdb"]["ports"] == [80]
        assert lk.lookup("93.184.215.9")["cached"] is True and len(urls) == 2
        # Survives a restart via SQLite.
        again = dossier.IpLookup(db_path=tmp_path / "e.db", fetch=fetch)
        assert again.cached("93.184.215.9")["rdap"]["network"] == "EXAMPLE-NET"

    def test_lookup_errors_are_reported(self):
        def boom(url, timeout):
            raise OSError("network down")

        out = dossier.IpLookup(fetch=boom, ptr=lambda ip: None).lookup("93.184.215.9")
        assert "rdap" in out["errors"] and out["rdap"] == {}

    def test_prefetch_policy(self):
        lk = dossier.IpLookup(fetch=lambda u, t: {}, ptr=lambda ip: None, mode="alerts")
        pre = dossier.LookupPrefetch(lk, min_severity=Severity.MEDIUM)
        pre.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.LOW, message="m", dst_ip="93.184.215.1"))
        pre.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="m", dst_ip="10.0.0.1"))
        pre.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="m", dst_ip="93.184.215.2"))
        assert lk._queued == {"93.184.215.2"}
        manual = dossier.IpLookup(fetch=lambda u, t: {}, mode="manual")
        assert manual.enqueue("93.184.215.3") is False


# ---------------------------------------------------------------------------
# LAN
# ---------------------------------------------------------------------------

ARP = """? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.20) at b8:27:eb:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.1.30) at (incomplete) on en0 ifscope [ethernet]
"""
NMAP = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<hostnames><hostname name="pi.lan"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>"""


class TestLan:
    def test_parse_arp(self):
        rows = lan.parse_arp(ARP)
        assert [r["ip"] for r in rows] == ["192.168.1.1", "192.168.1.20"]
        assert rows[0]["mac"] == "a4:2b:b0:01:02:03"
        assert lan.vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi"
        assert lan.is_randomized("da:00:00:00:00:01") and not lan.is_randomized("b8:27:eb:00:00:00")

    def test_new_device_after_learning(self, tmp_path):
        table = {"out": ARP}
        alerts = []
        inv_ = lan.LanInventory(db_path=tmp_path / "e.db", emit=alerts.append, arp=lambda: table["out"],
                                learning_seconds=0, hostname=lambda ip: "pi.local" if ip.endswith(".20") else None)
        inv_._created -= 10
        inv_.refresh()
        assert len(alerts) == 2  # learning window already over
        table["out"] = ARP + "? (192.168.1.40) at 3c:2a:f4:00:00:01 on en0 ifscope [ethernet]\n"
        inv_.refresh()
        assert len(alerts) == 3 and alerts[-1].rule_id == "LAN-NEW-DEVICE"
        assert alerts[-1].evidence["vendor"] == "Brother"
        assert classify(alerts[-1]) == "host"
        reloaded = lan.LanInventory(db_path=tmp_path / "e.db", arp=lambda: "")
        names = {d["ip"]: d.get("name") for d in reloaded.devices()}
        assert names["192.168.1.20"] == "pi.local" and len(names) == 3

    def test_quiet_during_learning(self, tmp_path):
        alerts = []
        lan.LanInventory(emit=alerts.append, arp=lambda: ARP, learning_seconds=3600).refresh()
        assert alerts == []

    def test_scan_rules(self):
        own = frozenset({"93.184.215.50"})
        assert lan.scan_allowed("192.168.1.20", own)
        assert lan.scan_allowed("93.184.215.50", own)  # this Mac
        assert not lan.scan_allowed("8.8.8.8", own)
        result = lan.parse_nmap_xml(NMAP)
        assert result["up"] and result["ports"] == [
            {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH 9.2"}]
        inv_ = lan.LanInventory(arp=lambda: "")
        with pytest.raises(PermissionError):
            inv_.scan("8.8.8.8", runner=lambda a, t: NMAP)
        assert inv_.scan("192.168.1.20", runner=lambda a, t: NMAP)["ports"][0]["port"] == 22


# ---------------------------------------------------------------------------
# Host-aware detectors
# ---------------------------------------------------------------------------

def out_meta(**kw):
    m = make_meta(src_ip="10.0.0.2", dst_ip="93.184.215.9", dst_port=443)
    m.update(kw)
    return m


def ctx(**kw):
    base = {"direction": "outbound", "remote_ip": "93.184.215.9", "app": "agent", "exe": "/tmp/agent", "pid": 7}
    base.update(kw)
    return {"context": base}


class TestProcessRisk:
    def test_alerts_once_per_exe(self):
        sigs = {"/tmp/agent": {"status": "unsigned"}}
        det = ProcessRiskDetector(sigs.get, persistence=lambda exe: [{"label": "com.x", "plist": "/p.plist"}])
        alerts = list(det.analyze(out_meta(), ctx(), None))
        assert len(alerts) == 1 and alerts[0].severity == Severity.HIGH
        assert alerts[0].evidence["launchd_jobs"][0]["label"] == "com.x"
        assert classify(alerts[0]) == "host"
        assert describe(alerts[0].to_dict())["verdict"] == "Act now"
        assert list(det.analyze(out_meta(), ctx(), None)) == []

    def test_waits_for_signature_and_skips_dev_tools(self):
        sigs = {}
        det = ProcessRiskDetector(sigs.get)
        assert list(det.analyze(out_meta(), ctx(), None)) == []  # unknown yet
        sigs["/tmp/agent"] = {"status": "unsigned"}
        assert len(list(det.analyze(out_meta(), ctx(), None))) == 1
        sigs["/opt/homebrew/bin/node"] = {"status": "adhoc"}
        assert list(det.analyze(out_meta(), ctx(exe="/opt/homebrew/bin/node", app="node"), None)) == []
        # LAN traffic is out of scope.
        sigs["/tmp/other"] = {"status": "unsigned"}
        assert list(det.analyze(out_meta(dst_ip="192.168.1.5"), ctx(exe="/tmp/other"), None)) == []


class TestBaseline:
    def test_learning_then_change(self, tmp_path):
        clock = {"t": 1000.0}
        store = BaselineStore(tmp_path / "e.db")
        persisted = store.created
        store.created = 1000.0
        det = BaselineDetector(store, learning_seconds=100, clock=lambda: clock["t"])
        c = ctx(exe="/Applications/Zoom.app/Contents/MacOS/zoom", app="zoom.us", country="US")
        assert list(det.analyze(out_meta(), c, None)) == []  # learning
        clock["t"] = 1200.0
        new_c = ctx(exe="/Applications/Zoom.app/Contents/MacOS/zoom", app="zoom.us", country="RU",
                    country_name="Russia")
        alerts = list(det.analyze(out_meta(), new_c, None))
        assert [a.rule_id for a in alerts] == ["BASELINE-NEW-COUNTRY"]
        assert alerts[0].evidence["usual_countries"] == ["US"]
        prog = list(det.analyze(out_meta(), ctx(exe="/tmp/new", app="new", signature="unsigned"), None))
        assert prog[0].rule_id == "HOST-NEW-PROGRAM" and prog[0].severity == Severity.MEDIUM
        # Browsers never get per-country alerts (a new browser binary is still a new program).
        fx = list(det.analyze(out_meta(), ctx(exe="/x/Firefox", app="Firefox", country="BR"), None))
        assert [a.rule_id for a in fx] == ["HOST-NEW-PROGRAM"]
        store.flush()
        reloaded = BaselineStore(tmp_path / "e.db")
        assert reloaded.created == persisted and reloaded.values("zoom.us", "country") == ["RU", "US"]


class TestC2Correlator:
    def test_two_independent_signals_fire_once(self):
        manager = AlertManager(dedup_window=0)
        sink = AlertCollector()
        manager.register_output(sink)
        manager.register_output(C2Correlator(emit=manager.add))
        context = {"exe": "/tmp/agent", "app": "agent", "remote_ip": "93.184.215.9", "direction": "outbound"}
        manager.add(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="untrusted",
                          rule_id="HOST-PROCESS-RISK", dst_ip="93.184.215.9", tags=["host_risk"],
                          context=dict(context)))
        assert not [a for a in sink.alerts if a.rule_id == "HOST-C2-LIKELY"]
        manager.add(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="beacon",
                          dst_ip="93.184.215.9", dst_port=443, tags=["beaconing"],
                          evidence={"hostname_known": False}, context=dict(context)))
        c2 = [a for a in sink.alerts if a.rule_id == "HOST-C2-LIKELY"]
        assert len(c2) == 1 and c2[0].severity == Severity.CRITICAL
        assert set(c2[0].evidence["signals"]) == {"untrusted_binary", "beacon", "bare_ip"}
        assert classify(c2[0]) == "threat"
        manager.add(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="beacon again",
                          dst_ip="93.184.215.9", dst_port=8443, tags=["beaconing"], context=dict(context)))
        assert len([a for a in sink.alerts if a.rule_id == "HOST-C2-LIKELY"]) == 1

    def test_beacon_alone_is_not_enough(self):
        fired = []
        corr = C2Correlator(emit=fired.append)
        corr.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.MEDIUM, message="b",
                        dst_ip="93.184.215.9", tags=["beaconing"], evidence={"hostname_known": False},
                        context={"app": "Mail", "remote_ip": "93.184.215.9"}))
        assert fired == []
        # …but a Shodan C2 tag on the server is a second, independent signal.
        corr = C2Correlator(emit=fired.append, infra_tags=lambda ip: ["c2"])
        corr.emit(Alert(alert_type=AlertType.BEHAVIORAL, severity=Severity.MEDIUM, message="b",
                        dst_ip="93.184.215.9", tags=["beaconing"], context={"app": "Mail", "remote_ip": "93.184.215.9"}))
        assert len(fired) == 1


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    def tracker(self, host="ads.doubleclick.net", app="Google Chrome"):
        return Alert(alert_type=AlertType.SIGNATURE, severity=Severity.LOW, message="t",
                     rule_id="STEALTH-TRACKER", tags=["tracker"],
                     context={"app": app, "remote_host": host, "remote_ip": "93.184.215.4"})

    def test_rules_and_filter(self, tmp_path):
        al = Allowlist(tmp_path / "allow.json")
        rule = al.add(kind="tracker", app="Google Chrome", host="doubleclick.net", note="ok")
        manager = AlertManager(dedup_window=0)
        sink = AlertCollector()
        manager.register_output(sink)
        manager.add_filter(al)
        manager.add(self.tracker())
        manager.add(self.tracker(app="Safari / WebKit"))
        assert [a.context["app"] for a in sink.alerts] == ["Safari / WebKit"]
        assert al.rules()[0]["hits"] == 1
        assert Allowlist(tmp_path / "allow.json").rules()[0]["id"] == rule["id"]
        assert al.remove(rule["id"]) and al.rules() == []

    def test_refuses_overbroad_rules(self):
        al = Allowlist()
        with pytest.raises(ValueError):
            al.add()
        with pytest.raises(ValueError):
            al.add(kind="threat")
        assert al.add(kind="threat", ip="93.184.215.4")


# ---------------------------------------------------------------------------
# Investigation agent
# ---------------------------------------------------------------------------

class FakeBeta:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        return self.responses.pop(0)


def tool_use(name, args, id_="t1"):
    return SimpleNamespace(type="tool_use", name=name, input=args, id=id_)


class TestInvestigate:
    def test_tools_are_strict_and_read_only(self):
        names = {t["name"] for t in inv.TOOLS}
        assert {"get_overview", "list_connections", "ip_dossier", "inspect_program"} <= names
        for t in inv.TOOLS:
            assert t["strict"] and t["input_schema"]["additionalProperties"] is False
            assert set(t["input_schema"]["required"]) == set(t["input_schema"]["properties"])
            assert not any(word in t["name"] for word in ("block", "kill", "scan", "delete"))

    def test_agent_loop(self, tmp_path):
        insp = make_inspector(tmp_path)
        box = inv.Toolbox(insp, insp.live)
        beta = FakeBeta([
            SimpleNamespace(stop_reason="tool_use", model="claude-opus-5-5", content=[
                tool_use("list_connections", {"only": "flagged", "app": None}),
                tool_use("inspect_program", {"exe": "relative"}, "t2")]),
            SimpleNamespace(stop_reason="end_turn", model="claude-opus-5-5", content=[
                SimpleNamespace(type="text", text="Verdict: Suspicious\n\n**Answer** — /tmp/agent.")]),
        ])
        out = inv.investigate("anything odd?", box, client=SimpleNamespace(beta=SimpleNamespace(messages=beta)))
        assert out["verdict"] == "Suspicious"
        assert [s["tool"] for s in out["steps"]] == ["list_connections", "inspect_program"]
        assert out["steps"][1]["ok"] is False  # bad input reported as a tool error
        second = beta.calls[1]
        # [question, assistant tool_use, user tool_results, final answer]
        results = second["messages"][2]["content"]
        assert results[0]["tool_use_id"] == "t1" and "/tmp/agent" in results[0]["content"]
        assert results[1]["is_error"] is True
        assert second["model"] == "claude-opus-5-5" and second["fallbacks"] == "default"
        assert "untrusted data" in second["system"]

    def test_refusal_and_empty_question(self, tmp_path):
        box = inv.Toolbox(make_inspector(tmp_path))
        refusing = FakeBeta([SimpleNamespace(stop_reason="refusal", model="m", content=[])])
        with pytest.raises(inv.ExplainError):
            inv.investigate("q", box, client=SimpleNamespace(beta=SimpleNamespace(messages=refusing)))
        with pytest.raises(inv.ExplainError):
            inv.investigate("  ", box, client=SimpleNamespace(beta=SimpleNamespace(messages=refusing)))


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@pytest.fixture
def host_api(tmp_path):
    live = LiveState()
    insp = make_inspector(tmp_path, live=live)
    ctx = ServiceContext(live=live, token="t0ken", inspector=insp, allowlist=Allowlist(tmp_path / "a.json"),
                         investigate=lambda q: {"text": "Verdict: Benign", "verdict": "Benign", "model": "m",
                                                "steps": [], "q": q})
    server = make_server(ctx, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def call(port, path, method="GET", body=None, token="t0ken", raw=False):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("X-PyNIDS-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read()
            return resp.status, data if raw else json.loads(data or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, None


class TestHostApi:
    def test_routes(self, host_api):
        code, snap = call(host_api, "/api/connections")
        assert code == 200 and snap["summary"]["flagged_programs"] == 1
        assert call(host_api, "/api/connections", token=None)[0] == 401
        code, att = call(host_api, "/api/attention")
        assert code == 200 and any("untrusted" in i["title"] for i in att["items"])
        assert call(host_api, "/api/program?exe=relative")[0] == 400
        assert call(host_api, "/api/dossier/nope")[0] == 400
        code, d = call(host_api, "/api/dossier/93.184.215.9")
        assert code == 200 and d["local"]["connected_now"]
        code, inv_ = call(host_api, "/api/investigate", method="POST", body={"question": "hi"})
        assert code == 200 and inv_["q"] == "hi"

    def test_allowlist_routes(self, host_api):
        code, rule = call(host_api, "/api/allowlist", method="POST", body={"kind": "tracker", "app": "Arc"})
        assert code == 201
        assert call(host_api, "/api/allowlist", method="POST", body={"kind": "attack"})[0] == 400
        assert len(call(host_api, "/api/allowlist")[1]) == 1
        assert call(host_api, f"/api/allowlist/{rule['id']}", method="DELETE")[1] == {"removed": True}

    def test_static_assets(self, host_api):
        code, body = call(host_api, "/static/topojson-client.min.js", token=None, raw=True)
        assert code == 200 and b"topojson" in body
        assert call(host_api, "/static/countries-110m.json", token=None, raw=True)[0] == 200
        assert call(host_api, "/static/README.md", token=None, raw=True)[0] == 404
        assert call(host_api, "/static/..%2Fapi.py", token=None, raw=True)[0] == 404


# ---------------------------------------------------------------------------
# Stop / quit leave nothing running
# ---------------------------------------------------------------------------

class TestStopAndQuit:
    def test_resolver_pause_stops_snapshots(self):
        from pynids.enrich import ProcessResolver
        calls = []
        r = ProcessResolver(min_interval=0.01, max_interval=0.05, snapshot=lambda: calls.append(1) or [])
        r.start()
        time.sleep(0.2)
        assert calls
        r.pause()
        time.sleep(0.1)
        before = len(calls)
        time.sleep(0.3)
        assert len(calls) == before and r.paused  # idle while paused
        r.resume()
        time.sleep(0.2)
        assert len(calls) > before
        r.stop()
        r._thread.join(1)
        assert not r._thread.is_alive()

    def test_resolver_stop_while_paused_exits(self):
        from pynids.enrich import ProcessResolver
        r = ProcessResolver(snapshot=lambda: [])
        r.start()
        r.pause()
        time.sleep(0.05)
        r.stop()
        r._thread.join(1)
        assert not r._thread.is_alive()

    def test_pf_unload_keeps_ledger(self, tmp_path):
        from pynids.response.pf import ANCHOR, PfBlocker
        calls = []
        runner = lambda args, stdin=None: calls.append(list(args)) or SimpleNamespace(  # noqa: E731
            returncode=0, stdout="Status: Enabled" if "-s" in args else "", stderr="")
        b = PfBlocker(ledger_path=tmp_path / "blocks.json", runner=runner)
        b._protected_ips = set()
        b.block("93.184.215.14", "bad", ttl=3600)
        b.unload()
        assert ["/sbin/pfctl", "-a", ANCHOR, "-F", "rules"] in calls
        # The block comes back on the next start.
        again = PfBlocker(ledger_path=tmp_path / "blocks.json", runner=runner)
        assert again.is_blocked("93.184.215.14")

    def test_kill_scans(self):
        import subprocess
        proc = subprocess.Popen(["/bin/sleep", "30"])
        lan._RUNNING.add(proc)
        lan.kill_scans()
        assert proc.wait(2) != 0
        lan._RUNNING.discard(proc)


def test_daemon_pause_and_shutdown(tmp_path, monkeypatch):
    """Stop idles detection work; shutdown releases the port and unloads pf."""
    monkeypatch.setenv("PYNIDS_HOME", str(tmp_path))
    from pynids.service.daemon import Daemon, DaemonOptions
    d = Daemon(DaemonOptions(no_capture=True, api_port=0,
                             extra={"lookups": {"mode": "manual"}, "host": {"lan_inventory": False}}))
    unloaded = []
    d.blocker = SimpleNamespace(unload=lambda: unloaded.append(1))
    if d.processes:
        d.processes.start()
    d.set_detection(False)
    assert d.paused and (d.processes is None or d.processes.paused)
    assert (tmp_path / "paused").exists()
    d.set_detection(True)
    assert not d.paused and (d.processes is None or not d.processes.paused)
    threading.Thread(target=d.server.serve_forever, daemon=True).start()
    port = d.server.server_address[1]
    d.shutdown()
    assert unloaded == [1]
    import socket
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1)
