"""Regression tests for the service hardening: pf input, auth, CSP, restarts, updater."""
from __future__ import annotations

import http.client
import json
import os
import re
import stat
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from pynids.response.pf import BlockEntry, BlockRefused, PfBlocker
from pynids.service import daemon as daemon_mod
from pynids.service.api import ServiceContext, make_server, session_value
from pynids.service.live import LiveState
from pynids.service.updater import Updater

TOKEN = "t0ken-value"


class FakePf:
    def __init__(self):
        self.calls = []

    def __call__(self, args, stdin=None):
        self.calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="Status: Enabled" if "-s" in args else "", stderr="")


def make_blocker(tmp_path, **kw):
    runner = FakePf()
    blocker = PfBlocker(ledger_path=tmp_path / "blocks.json", runner=runner, **kw)
    blocker._protected_ips = {"203.0.113.1"}
    return blocker, runner


@pytest.fixture
def server(tmp_path):
    started = []

    def start(**kw):
        ctx = ServiceContext(live=kw.pop("live", LiveState()), token=TOKEN,
                             status=lambda: {"state": "running"}, **kw)
        srv = make_server(ctx, "127.0.0.1", 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return SimpleNamespace(port=srv.server_address[1], ctx=ctx)

    yield start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def request(port, method, path, body=None, headers=None, token=TOKEN, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Host": f"127.0.0.1:{port}", **(headers or {})}
    if token:
        hdrs["X-PyNIDS-Token"] = token
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if data is not None and "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(data))
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in hdrs.items():
        conn.putheader(k, v)
    conn.endheaders(data)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp, payload


# ---------------------------------------------------------------------------
# pf input validation
# ---------------------------------------------------------------------------

def test_unblock_rejects_options_and_garbage_without_calling_pfctl(server, tmp_path):
    blocker, pf = make_blocker(tmp_path)
    srv = server(blocker=blocker)
    for bad in ("-d", "%2Dd", "-F%20all", "garbage", "1.2.3.4%20-d", "%20"):
        resp, _ = request(srv.port, "DELETE", f"/api/blocks/{bad}")
        assert resp.status == 400, bad
    resp, _ = request(srv.port, "POST", "/api/blocks", body={"ip": "-d", "ttl": 60})
    assert resp.status == 400
    assert pf.calls == []
    with pytest.raises(ValueError):
        blocker.unblock("-d")
    assert pf.calls == []


def test_unblock_canonicalizes(server, tmp_path):
    blocker, pf = make_blocker(tmp_path)
    srv = server(blocker=blocker)
    resp, body = request(srv.port, "POST", "/api/blocks", body={"ip": "2606:4700:0::1111", "ttl": 600})
    assert resp.status == 201 and json.loads(body)["ip"] == "2606:4700::1111"
    resp, body = request(srv.port, "DELETE", "/api/blocks/2606:4700:0:0::1111")
    assert resp.status == 200 and json.loads(body) == {"ip": "2606:4700::1111", "removed": True}
    assert pf.calls[-1][-1] == "2606:4700::1111"


def test_ipv6_protected_guard_is_canonical(tmp_path):
    blocker, _ = make_blocker(tmp_path)
    blocker._protected_ips = {"2001:4860:4860:0:0:0:0:8888"}  # as some tool might print it
    for spelling in ("2001:4860:4860::8888", "2001:4860:4860:0::8888", "2001:4860:4860:0000::8888"):
        with pytest.raises(BlockRefused):
            blocker.block(spelling, "x")
    entry = blocker.block("2606:4700:0::1111", "x", ttl=60)
    assert entry.ip == "2606:4700::1111" and blocker.is_blocked("2606:4700:0:0::1111")


def test_protected_ips_are_refreshed(tmp_path, monkeypatch):
    blocker, _ = make_blocker(tmp_path)
    monkeypatch.setattr("pynids.response.pf._system_critical_ips", lambda: ["9.9.9.9"])
    blocker._protected_at -= 3600  # stale
    with pytest.raises(BlockRefused):
        blocker.block("9.9.9.9", "new DNS server")


def test_pfctl_timeout_does_not_escape(tmp_path):
    import subprocess

    def slow(args, stdin=None):
        raise subprocess.TimeoutExpired(args, 15)

    blocker = PfBlocker(ledger_path=tmp_path / "b.json", runner=slow)
    blocker._entries.clear()
    blocker.unblock("93.184.215.14")  # check=False: logged, not raised
    blocker._entries["93.184.215.14"] = BlockEntry("93.184.215.14", "x", created=0, expires=1)
    assert blocker.expire() == ["93.184.215.14"]
    with pytest.raises(RuntimeError):
        blocker.block("93.184.215.14", "x")


# ---------------------------------------------------------------------------
# ttl / body parsing
# ---------------------------------------------------------------------------

def test_block_ttl_zero_or_null_gets_default_and_bounds(server, tmp_path):
    blocker, _ = make_blocker(tmp_path)
    srv = server(blocker=blocker)
    for ttl in (0, None, ""):
        resp, body = request(srv.port, "POST", "/api/blocks", body={"ip": "93.184.215.14", "ttl": ttl})
        e = json.loads(body)
        assert resp.status == 201 and e["expires"] is not None
        assert 3590 < e["expires"] - e["created"] <= 3600
    _, body = request(srv.port, "POST", "/api/blocks", body={"ip": "93.184.215.14", "ttl": 1})
    e = json.loads(body)
    assert e["expires"] - e["created"] == pytest.approx(60)
    _, body = request(srv.port, "POST", "/api/blocks", body={"ip": "93.184.215.14", "ttl": 10 ** 12})
    e = json.loads(body)
    assert e["expires"] - e["created"] == pytest.approx(7 * 86400)
    for bad in ("soon", [1], {"a": 1}, True, "nan"):
        resp, _ = request(srv.port, "POST", "/api/blocks", body={"ip": "93.184.215.14", "ttl": bad})
        assert resp.status == 400, bad
    # The blocker itself never makes a permanent block either.
    assert blocker.block("93.184.215.15", "x", ttl=None).expires is not None


def test_bad_content_length_is_400(server):
    srv = server(set_detection=lambda on: {"enabled": on})
    for value in ("abc", "-5", "1e3", "12 34"):
        resp, _ = request(srv.port, "POST", "/api/detection", raw=b"{}", headers={"Content-Length": value})
        assert resp.status == 400, value


def test_allowlist_ip_is_validated(server, tmp_path):
    from pynids.alerts.allowlist import Allowlist
    srv = server(allowlist=Allowlist(tmp_path / "allow.json"))
    resp, _ = request(srv.port, "POST", "/api/allowlist", body={"ip": "not-an-ip"})
    assert resp.status == 400
    resp, body = request(srv.port, "POST", "/api/allowlist", body={"ip": "2001:db8:0::1"})
    assert resp.status == 201 and json.loads(body)["ip"] == "2001:db8::1"


# ---------------------------------------------------------------------------
# Dashboard auth contract + CSP
# ---------------------------------------------------------------------------

def test_auth_query_redirects_with_session_cookie(server):
    srv = server()
    resp, _ = request(srv.port, "GET", f"/?auth={TOKEN}", token=None)
    assert resp.status == 303 and resp.getheader("Location") == "/"
    cookie = resp.getheader("Set-Cookie")
    assert cookie == f"pynids_session={session_value(TOKEN)}; HttpOnly; SameSite=Strict; Path=/"
    import hashlib
    import hmac
    assert session_value(TOKEN) == hmac.new(TOKEN.encode(), b"pynids-session", hashlib.sha256).hexdigest()
    # A wrong token gets the locked page, no cookie.
    resp, body = request(srv.port, "GET", "/?auth=wrong", token=None)
    assert resp.status == 401 and resp.getheader("Set-Cookie") is None and b"pynids open" in body


def test_cookie_unlocks_dashboard_and_api(server):
    srv = server()
    cookie = {"Cookie": f"other=1; pynids_session={session_value(TOKEN)}"}
    resp, body = request(srv.port, "GET", "/", token=None, headers=cookie)
    assert resp.status == 200 and b"PyNIDS" in body
    assert TOKEN.encode() not in body
    assert request(srv.port, "GET", "/api/summary", token=None, headers=cookie)[0].status == 200
    bad = {"Cookie": "pynids_session=" + "0" * 64}
    assert request(srv.port, "GET", "/api/summary", token=None, headers=bad)[0].status == 401
    # A stale header doesn't cancel a valid cookie; ?token= still works for old clients.
    assert request(srv.port, "GET", "/api/summary", token="stale", headers=cookie)[0].status == 200
    assert request(srv.port, "GET", f"/api/summary?token={TOKEN}", token=None)[0].status == 200


def test_dashboard_without_cookie_is_locked(server):
    srv = server()
    resp, body = request(srv.port, "GET", "/", token=None)
    assert resp.status == 401
    assert b"pynids open" in body and b"menu bar" in body
    assert TOKEN.encode() not in body
    assert b"<script" not in body
    # The X-PyNIDS-Token header alone doesn't render the dashboard either (cookie only).
    resp, body = request(srv.port, "GET", "/", token=TOKEN)
    assert resp.status == 401


def test_dashboard_csp_nonce_matches_inline_scripts(server):
    srv = server()
    cookie = {"Cookie": f"pynids_session={session_value(TOKEN)}"}
    resp, body = request(srv.port, "GET", "/", token=None, headers=cookie)
    csp = resp.getheader("Content-Security-Policy")
    m = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_\-]+)'", csp)
    assert m, csp
    for directive in ("default-src 'self'", "object-src 'none'", "base-uri 'none'",
                      "frame-ancestors 'none'", "frame-src 'self' about:", "style-src 'self' 'unsafe-inline'"):
        assert directive in csp
    html = body.decode()
    inline = [t for t in re.findall(r"<script\b[^>]*>", html) if "src=" not in t]
    assert inline and all(f'nonce="{m.group(1)}"' in t for t in inline)
    assert "__PYNIDS_NONCE__" not in html and TOKEN not in html
    # Fresh nonce per response.
    resp2, _ = request(srv.port, "GET", "/", token=None, headers=cookie)
    assert resp2.getheader("Content-Security-Policy") != csp


def test_nonce_placeholder_is_supported(server, monkeypatch):
    from pynids.service import api

    class FakeFile:
        def joinpath(self, *a):
            return self

        def read_text(self, enc):
            return '<html><script nonce="__PYNIDS_NONCE__">x()</script><script src="/static/a.js"></script></html>'

    monkeypatch.setattr(api.resources, "files", lambda pkg: FakeFile())
    srv = server()
    resp, body = request(srv.port, "GET", "/", token=None,
                         headers={"Cookie": f"pynids_session={session_value(TOKEN)}"})
    nonce = re.search(r"'nonce-([^']+)'", resp.getheader("Content-Security-Policy")).group(1)
    assert body.decode() == (f'<html><script nonce="{nonce}">x()</script>'
                             '<script src="/static/a.js"></script></html>')


def test_widget_is_cached(server):
    calls = []
    insp = SimpleNamespace(connections=lambda **kw: calls.append(1) or {"summary": {"flagged_programs": 0}},
                           lan=None)
    srv = server(inspector=insp)
    for _ in range(5):
        assert request(srv.port, "GET", "/api/widget", token=None)[0].status == 200
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# SSE ends on shutdown
# ---------------------------------------------------------------------------

def test_stream_handlers_end_when_streams_close(server):
    live = LiveState()
    srv = server(live=live)
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    conn.request("GET", "/api/stream", headers={"X-PyNIDS-Token": TOKEN})
    resp = conn.getresponse()
    assert resp.status == 200
    resp.fp.readline()  # "retry: 3000"
    deadline = time.time() + 2
    while not live._subscribers and time.time() < deadline:
        time.sleep(0.01)
    assert live._subscribers
    live.close_streams()
    deadline = time.time() + 5
    while live._subscribers and time.time() < deadline:
        time.sleep(0.05)
    assert not live._subscribers
    conn.close()


# ---------------------------------------------------------------------------
# Daemon: periodic loop, restart, notifications, file modes
# ---------------------------------------------------------------------------

def bare_daemon(**attrs):
    d = object.__new__(daemon_mod.Daemon)
    d.cfg = {"daemon": {"feed_refresh_hours": 0, "interface": "auto", "retention_days": 0}}
    d.stop_event = threading.Event()
    d.capture_stop = threading.Event()
    d.live = LiveState()
    d.baseline = d.lan = d.blocker = None
    d.paused = False
    d.interfaces = []
    d._last_error_log = {}
    d._restart_requested = False
    d._TICK = 0.001
    for k, v in attrs.items():
        setattr(d, k, v)
    return d


def test_periodic_survives_failing_subtasks():
    import sqlite3
    expired = []

    def locked():
        raise sqlite3.OperationalError("database is locked")

    def expire():
        expired.append(1)
        if len(expired) == 1:
            raise RuntimeError("pfctl timed out")
        return []

    d = bare_daemon(store=SimpleNamespace(flush=locked, prune=locked),
                    baseline=SimpleNamespace(store=SimpleNamespace(flush=locked)),
                    blocker=SimpleNamespace(expire=expire))
    t = threading.Thread(target=d._periodic, daemon=True)
    t.start()
    deadline = time.time() + 10
    while len(expired) < 3 and time.time() < deadline:
        time.sleep(0.01)
    d.stop_event.set()
    t.join(5)
    assert len(expired) >= 3 and not t.is_alive()


def test_network_change_by_hand_moves_capture_in_place(monkeypatch):
    moved = []
    monkeypatch.setattr(daemon_mod, "default_interface", lambda: "en7")
    monkeypatch.setattr(daemon_mod, "_under_launchd", lambda: False)
    d = bare_daemon(interfaces=["en0"])
    d._restart_capture = lambda: moved.append(1)
    d._follow_default_route()
    assert moved == [1] and not d._restart_requested
    monkeypatch.setattr(daemon_mod, "_under_launchd", lambda: True)
    d._follow_default_route()
    assert d._restart_requested and d.stop_event.is_set()


def test_restart_code_reexecs_the_process(monkeypatch):
    from click.testing import CliRunner
    from pynids.cli_service import daemon_run

    execs = []
    monkeypatch.setattr(daemon_mod, "run_daemon", lambda options: 75)
    monkeypatch.setattr(daemon_mod.os, "execv", lambda exe, argv: execs.append((exe, argv)))
    monkeypatch.setattr(sys, "argv", ["/venv/bin/pynids", "daemon", "run", "--port", "9999"])
    CliRunner().invoke(daemon_run, ["--port", "9999"])
    assert execs == [(sys.executable, [sys.executable, "-m", "pynids", "daemon", "run", "--port", "9999"])]

    execs.clear()
    monkeypatch.setattr(daemon_mod, "run_daemon", lambda options: 0)
    result = CliRunner().invoke(daemon_run, [])
    assert result.exit_code == 0 and execs == []


def test_notification_toggle_persists(tmp_path, monkeypatch):
    monkeypatch.setenv("PYNIDS_HOME", str(tmp_path))
    from pynids.paths import notifications_off_flag_path
    d = bare_daemon(notifier=SimpleNamespace(enabled=True))
    assert d.set_notifications(False) is False and notifications_off_flag_path().exists()
    assert d.notifier.enabled is False
    assert d.set_notifications(True) is True and not notifications_off_flag_path().exists()

    calls = []
    ctx_notifier = SimpleNamespace(enabled=True)
    ctx = ServiceContext(live=LiveState(), token=TOKEN, notifier=ctx_notifier,
                         set_notifications=lambda on: calls.append(on) or on)
    srv = make_server(ctx, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        resp, body = request(srv.server_address[1], "POST", "/api/notifications", body={"enabled": False})
        assert resp.status == 200 and json.loads(body) == {"enabled": False} and calls == [False]
    finally:
        srv.shutdown()
        srv.server_close()


def test_token_file_is_private(tmp_path, monkeypatch):
    monkeypatch.setenv("PYNIDS_HOME", str(tmp_path))
    (tmp_path / "api-token").write_text("old\n")
    os.chmod(tmp_path / "api-token", 0o644)
    assert daemon_mod.ensure_token() == "old"
    assert stat.S_IMODE(os.stat(tmp_path / "api-token").st_mode) == 0o600
    (tmp_path / "api-token").unlink()
    token = daemon_mod.ensure_token()
    assert len(token) > 20 and stat.S_IMODE(os.stat(tmp_path / "api-token").st_mode) == 0o600
    from pynids.paths import read_api_token
    assert read_api_token() == token


def test_harden_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("PYNIDS_HOME", str(tmp_path))
    (tmp_path / "events.db").write_text("")
    (tmp_path / "captures").mkdir()
    (tmp_path / "captures" / "a.pcap").write_text("")
    (tmp_path / "intel").mkdir()
    (tmp_path / "intel" / "feed.json").write_text("{}")
    for p in (tmp_path / "events.db", tmp_path / "captures" / "a.pcap", tmp_path / "intel" / "feed.json"):
        os.chmod(p, 0o644)
    os.chmod(tmp_path / "captures", 0o755)
    os.chmod(tmp_path / "intel", 0o700)
    daemon_mod.harden_permissions()
    mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)  # noqa: E731
    assert mode(tmp_path) == 0o711
    assert mode(tmp_path / "events.db") == 0o600
    assert mode(tmp_path / "captures") == 0o700 and mode(tmp_path / "captures" / "a.pcap") == 0o600
    assert mode(tmp_path / "intel") == 0o755 and mode(tmp_path / "intel" / "feed.json") == 0o644


def test_dashboard_link_carries_token():
    from pynids.service.client import ApiClient
    c = ApiClient(token="a/b+c", port=8787)
    assert c.dashboard_link("#events") == "http://127.0.0.1:8787/?auth=a%2Fb%2Bc#events"


# ---------------------------------------------------------------------------
# Updater
# ---------------------------------------------------------------------------

def test_updater_lock_released_when_on_restart_raises(tmp_path, monkeypatch):
    def boom():
        raise RuntimeError("cannot restart")

    upd = Updater(repo=tmp_path, on_restart=boom)
    monkeypatch.setattr(upd, "_check_locked", lambda: upd._update(behind=1, blocked=None, branch="main",
                                                                  latest_version="9.9"))
    monkeypatch.setattr(upd, "_git", lambda *a, **kw: "0123456789abcdef" if a[0] == "rev-parse" else "")
    monkeypatch.setattr(upd, "_run", lambda *a, **kw: "")
    monkeypatch.setattr("pynids.service.updater.time.sleep", lambda s: None)
    upd.apply()
    deadline = time.time() + 5
    while time.time() < deadline:
        if upd._lock.acquire(blocking=False):
            upd._lock.release()
            break
        time.sleep(0.02)
    else:
        raise AssertionError("update lock never released")
    assert upd.status()["state"] == "restart-needed"


def test_updater_status_is_a_copy(tmp_path):
    upd = Updater(repo=tmp_path)
    upd._update(commits=[{"sha": "a"}])
    info = upd.status()
    info["commits"].append({"sha": "b"})
    info["state"] = "hacked"
    assert upd.status()["commits"] == [{"sha": "a"}] and upd.status()["state"] == "idle"


def test_failed_update_reinstalls_previous_dependencies(tmp_path, monkeypatch):
    upd = Updater(repo=tmp_path, on_restart=lambda: None)
    runs, gits = [], []
    monkeypatch.setattr(upd, "_check_locked", lambda: upd._update(behind=1, blocked=None, branch="main"))

    def git(*a, **kw):
        gits.append(a)
        if a[0] == "rev-parse":
            return "0123456789abcdef"
        if a[0] == "diff":
            return "pyproject.toml"
        return ""

    def run(*a, **kw):
        runs.append(a)
        if "-c" in a:
            raise RuntimeError("import failed")
        return ""

    monkeypatch.setattr(upd, "_git", git)
    monkeypatch.setattr(upd, "_run", run)
    upd.apply()
    deadline = time.time() + 5
    while upd.status()["state"] != "error" and time.time() < deadline:
        time.sleep(0.02)
    assert upd.status()["state"] == "error"
    assert any(a[0] == "reset" for a in gits)
    pips = [a for a in runs if "pip" in a]
    assert len(pips) == 2  # the update's install, then the rollback's
