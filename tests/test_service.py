"""Enrichment, response (pf / notifications), storage, live state, API, Claude module."""
from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from pynids.ai import explain as ai
from pynids.alerts.model import Alert, AlertType, Severity
from pynids.alerts.outputs.sqlite_out import SQLiteOutput
from pynids.enrich import Enricher, HostnameCache, ProcessResolver
from pynids.enrich.process import app_name_from_exe
from pynids.response.notify import NotificationOutput
from pynids.response.pf import ANCHOR, AutoBlockPolicy, BlockRefused, PfBlocker
from pynids.service.api import ServiceContext, make_server
from pynids.service.live import LiveState
from tests.conftest import make_meta


def alert(**kw) -> Alert:
    base = dict(alert_type=AlertType.BEHAVIORAL, severity=Severity.HIGH, message="m",
                src_ip="10.0.0.2", dst_ip="93.184.215.14", rule_id="R")
    base.update(kw)
    return Alert(**base)


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

class TestEnrichment:
    @pytest.mark.parametrize("exe,name,expected", [
        ("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/"
         "Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
         "Google Chrome Helper (Renderer)", "Google Chrome"),
        ("/usr/sbin/mDNSResponder", "mDNSResponder", "mDNSResponder"),
        ("/Users/x/.local/share/claude/versions/2.1.0", "2.1.0", "claude"),
        ("", "curl", "curl"),
    ])
    def test_app_names(self, exe, name, expected):
        assert app_name_from_exe(exe, name) == expected

    def test_packet_context(self):
        proc = {"pid": 42, "process": "firefox", "app": "Firefox", "exe": "", "user": "u"}
        resolver = ProcessResolver(snapshot=lambda: [("tcp", 50001, proc)])
        resolver.refresh()
        hosts = HostnameCache()
        enricher = Enricher(processes=resolver, hostnames=hosts, local_ips=frozenset({"10.0.0.2"}))
        dns = {"dns": {"query_name": "example.com", "answers": [{"type": "A", "data": "93.184.215.14", "name": "example.com"}]}}
        enricher.packet_context(make_meta(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=53, dst_port=5000, protocol="udp"), dns)

        out = enricher.packet_context(make_meta(src_ip="10.0.0.2", dst_ip="93.184.215.14", src_port=50001, dst_port=443), {})
        assert out["direction"] == "outbound" and out["remote_ip"] == "93.184.215.14"
        assert out["app"] == "Firefox" and out["pid"] == 42
        assert out["remote_host"] == "example.com"

        back = enricher.packet_context(make_meta(src_ip="93.184.215.14", dst_ip="10.0.0.2", src_port=443, dst_port=50001), {})
        assert back["direction"] == "inbound" and back["app"] == "Firefox"

    def test_resolver_forgets_after_memory_window(self):
        rows = [("udp", 5353, {"pid": 1, "process": "p", "app": "p", "exe": "", "user": ""})]
        r = ProcessResolver(snapshot=lambda: rows, memory_seconds=-1)
        r.refresh()
        rows.clear()
        r.refresh()
        assert r.lookup("udp", 5353) is None


# ---------------------------------------------------------------------------
# pf blocking
# ---------------------------------------------------------------------------

class FakePf:
    def __init__(self):
        self.calls = []

    def __call__(self, args, stdin=None):
        self.calls.append((list(args), stdin))
        out = "Status: Enabled" if "-s" in args else ""
        return SimpleNamespace(returncode=0, stdout=out, stderr="")


class TestPfBlocker:
    def make(self, tmp_path, **kw):
        runner = FakePf()
        blocker = PfBlocker(ledger_path=tmp_path / "blocks.json", runner=runner, **kw)
        blocker._protected_ips = {"203.0.113.1"}  # pretend gateway
        return blocker, runner

    def test_guard_rails(self, tmp_path):
        b, _ = self.make(tmp_path, never_block=["198.51.100.0/24"])
        for ip in ("192.168.1.10", "127.0.0.1", "fe80::1", "224.0.0.251", "203.0.113.1", "198.51.100.7", "nope"):
            with pytest.raises(BlockRefused):
                b.block(ip, "x")

    def test_block_unblock_and_ledger(self, tmp_path):
        b, pf = self.make(tmp_path)
        b.block("93.184.215.14", "bad", ttl=60)
        cmds = [c[0] for c in pf.calls]
        assert ["/sbin/pfctl", "-a", ANCHOR, "-f", "-"] in cmds
        assert ["/sbin/pfctl", "-a", ANCHOR, "-t", "pynids_block", "-T", "add", "93.184.215.14"] in cmds
        assert "block drop quick" in [c[1] for c in pf.calls if c[1]][0]
        # Ledger survives a restart.
        again, _ = self.make(tmp_path)
        assert again.is_blocked("93.184.215.14")
        assert again.unblock("93.184.215.14")
        assert not again.list()

    def test_expiry(self, tmp_path):
        b, _ = self.make(tmp_path)
        b.block("93.184.215.14", "bad", ttl=-1)
        assert b.expire() == ["93.184.215.14"]

    def test_dry_run_never_calls_pfctl(self, tmp_path):
        b, pf = self.make(tmp_path, dry_run=True)
        b.block("93.184.215.14", "bad")
        assert pf.calls == []

    def test_auto_block_policy(self, tmp_path):
        b, _ = self.make(tmp_path)
        policy = AutoBlockPolicy(b, min_severity=Severity.CRITICAL)
        policy.emit(alert(severity=Severity.CRITICAL))  # behavioural → ignored
        assert not b.list()
        policy.emit(alert(alert_type=AlertType.THREAT_INTEL, severity=Severity.HIGH))  # below threshold
        assert not b.list()
        policy.emit(alert(alert_type=AlertType.THREAT_INTEL, severity=Severity.CRITICAL,
                          context={"remote_ip": "93.184.215.14", "direction": "outbound"}))
        assert b.is_blocked("93.184.215.14")


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

class TestNotifications:
    def test_threshold_and_coalescing(self):
        posted = []
        done = threading.Event()

        def poster(title, message, subtitle="", sound=False):
            posted.append((title, message, subtitle, sound))
            done.set()
            return True

        out = NotificationOutput(min_severity=Severity.HIGH, min_interval=0.2, poster=poster)
        out.emit(alert(severity=Severity.LOW))
        out.emit(alert(severity=Severity.HIGH, message="first"))
        assert done.wait(2)
        done.clear()
        out.emit(alert(severity=Severity.HIGH, message="second"))
        out.emit(alert(severity=Severity.CRITICAL, message="third", context={"app": "Safari"}))
        assert done.wait(2)
        assert len(posted) == 2
        assert posted[1][0] == "PyNIDS · 2 new alerts"
        assert posted[1][1] == "third" and "Safari" in posted[1][2] and posted[1][3] is True


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------

class TestSqlite:
    def test_migrates_old_schema_and_stores_context(self, tmp_path):
        db = tmp_path / "old.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, "
                     "alert_type TEXT NOT NULL, severity TEXT NOT NULL, severity_numeric INTEGER NOT NULL, "
                     "message TEXT NOT NULL, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, "
                     "protocol TEXT, rule_id TEXT, flow_id TEXT, confidence REAL, tags TEXT, "
                     "mitre_technique TEXT, evidence TEXT)")
        conn.commit()
        conn.close()
        out = SQLiteOutput(str(db), batch_size=0)
        out.emit(alert(context={"app": "Slack", "remote_host": "slack.com", "country": "US"}))
        out.close()
        row = sqlite3.connect(db).execute("SELECT app, remote_host, country FROM alerts").fetchone()
        assert row == ("Slack", "slack.com", "US")


# ---------------------------------------------------------------------------
# Live state + API
# ---------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path):
    live = LiveState()
    explained = []

    def fake_explain(a):
        explained.append(a["alert_id"])
        return {"text": "Verdict: Benign\n\n**What happened** — ok", "verdict": "Benign", "model": "m"}

    ctx = ServiceContext(live=live, token="t0ken", db_path=tmp_path / "events.db",
                         status=lambda: {"state": "running"}, explain=fake_explain)
    server = make_server(ctx, "127.0.0.1", 0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield SimpleNamespace(live=live, port=port, explained=explained)
    server.shutdown()
    server.server_close()


def call(port, path, token="t0ken", method="GET", body=None, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("X-PyNIDS-Token", token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


class TestApi:
    def test_security(self, api):
        assert call(api.port, "/api/health", token=None)[0] == 200
        assert call(api.port, "/api/widget", token=None)[0] == 200
        assert call(api.port, "/api/summary", token=None)[0] == 401
        assert call(api.port, "/api/summary", token="wrong")[0] == 401
        assert call(api.port, "/api/health", headers={"Host": f"attacker.test:{api.port}"})[0] == 403
        code, _ = call(api.port, "/api/notifications", method="POST", body={},
                       headers={"Origin": "https://attacker.test"})
        assert code == 403

    def test_live_data_flow(self, api):
        api.live.observe_packet(dict(make_meta(), packet_len=1500), {}, {
            "direction": "outbound", "remote_ip": "93.184.215.14", "app": "Safari",
            "remote_host": "example.com", "country": "US", "lat": 1.0, "lon": 2.0})
        a = alert(severity=Severity.CRITICAL, context={"app": "Safari", "remote_ip": "93.184.215.14"})
        api.live.emit(a)
        code, s = call(api.port, "/api/summary")
        assert code == 200 and s["level"] == "critical" and s["events_total"] == 1
        assert s["status"]["state"] == "running"
        _, apps = call(api.port, "/api/apps")
        assert apps[0]["app"] == "Safari" and apps[0]["alerts"] == 1
        _, remotes = call(api.port, "/api/remotes")
        assert remotes[0]["remote_host"] == "example.com" and remotes[0]["apps"] == ["Safari"]
        _, w = call(api.port, "/api/widget", token=None)
        assert w["last_alert"]["app"] == "Safari"

    def test_explain_is_cached(self, api):
        a = alert()
        api.live.emit(a)
        code, r = call(api.port, f"/api/explain/{a.alert_id}", method="POST", body={})
        assert code == 200 and r["verdict"] == "Benign" and r["cached"] is False
        _, r2 = call(api.port, f"/api/explain/{a.alert_id}", method="POST", body={})
        assert r2["cached"] is True and api.explained == [a.alert_id]

    def test_blocks_unavailable_without_blocker(self, api):
        assert call(api.port, "/api/blocks")[0] == 501


# ---------------------------------------------------------------------------
# Claude explanations
# ---------------------------------------------------------------------------

class TestExplain:
    def test_parse_verdict(self):
        assert ai.parse_verdict("Verdict: Privacy concern\n\nstuff") == "Privacy concern"
        assert ai.parse_verdict("**Verdict:** Malicious") == "Malicious"
        assert ai.parse_verdict("no verdict here") is None

    def test_request_shape_and_refusal(self):
        captured = {}

        class Messages:
            def create(self, **kw):
                captured.update(kw)
                return SimpleNamespace(stop_reason="end_turn", model="claude-opus-5",
                                       content=[SimpleNamespace(type="text", text="Verdict: Benign\n\nFine.")])

        client = SimpleNamespace(beta=SimpleNamespace(messages=Messages()))
        out = ai.explain_alert(alert().to_dict(), client=client)
        assert out["verdict"] == "Benign"
        assert captured["model"] == "claude-opus-5"
        assert captured["fallbacks"] == "default"
        assert captured["betas"] == ["server-side-fallback-2026-07-01"]
        assert "untrusted" in captured["system"]

        class Refusing:
            def create(self, **kw):
                return SimpleNamespace(stop_reason="refusal", model="m", content=[])

        with pytest.raises(ai.ExplainError):
            ai.explain_alert(alert().to_dict(), client=SimpleNamespace(beta=SimpleNamespace(messages=Refusing())))
