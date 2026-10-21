"""In-app updates: check GitHub (here: a local bare repo), fast-forward, roll back."""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from pynids.service.updater import Updater, UpdateError, https_url

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def commit(repo: Path, path: str, text: str, message: str) -> None:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(text)
    git(repo, "add", path)
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", message)


@pytest.fixture
def repos(tmp_path):
    """(local checkout, upstream working copy) sharing a bare 'GitHub' remote."""
    bare, up, local = tmp_path / "origin.git", tmp_path / "upstream", tmp_path / "local"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(bare))
    git(tmp_path, "clone", "-q", str(bare), str(up))
    git(up, "checkout", "-q", "-b", "main")
    commit(up, "pynids/__init__.py", '__version__ = "2.0.0"\n', "initial")
    commit(up, "pyproject.toml", "[project]\n", "pyproject")
    git(up, "push", "-q", "origin", "main")
    git(tmp_path, "clone", "-q", str(bare), str(local))
    return local, up


def push(up: Path, path: str, text: str, message: str) -> None:
    commit(up, path, text, message)
    git(up, "push", "-q", "origin", "main")


def wait(updater: Updater, *states: str, timeout: float = 30) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = updater.status()
        if info["state"] in states:
            return info
        time.sleep(0.05)
    raise AssertionError(f"updater stuck in {updater.status()['state']}")


def test_https_url():
    assert https_url("git@github.com:Rarees404/NIDS.git") == "https://github.com/Rarees404/NIDS.git"
    assert https_url("ssh://git@github.com/o/r.git") == "https://github.com/o/r.git"
    assert https_url("https://github.com/o/r.git") == "https://github.com/o/r.git"


def test_up_to_date(repos):
    local, _ = repos
    info = Updater(repo=local).check()
    assert info["available"] is False and info["behind"] == 0 and not info.get("error")


def test_check_and_apply(repos, tmp_path):
    local, up = repos
    push(up, "pynids/__init__.py", '__version__ = "2.1.0"\n', "Bump to 2.1.0")
    push(up, "macos/src/App.swift", "// new\n", "New menu bar feature")

    restarted = threading.Event()
    state_file = tmp_path / "last-update.json"
    events = []
    upd = Updater(repo=local, state_file=state_file, on_restart=restarted.set,
                  broadcast=lambda kind, data: events.append(data["state"]))
    info = upd.check()
    assert info["available"] and info["behind"] == 2 and info["latest_version"] == "2.1.0"
    assert [c["subject"] for c in info["commits"]] == ["New menu bar feature", "Bump to 2.1.0"]
    assert info["blocked"] is None

    upd.apply()
    assert restarted.wait(30), upd.status()
    assert upd.status()["state"] == "restarting"
    assert (local / "macos/src/App.swift").exists()
    assert git(local, "rev-parse", "HEAD") == git(up, "rev-parse", "HEAD")
    record = json.loads(state_file.read_text())
    assert record["version"] == "2.1.0" and record["app_changed"] is True
    assert "updating" in events and "restarting" in events


def test_uncommitted_edit_to_changed_file_blocks(repos):
    local, up = repos
    push(up, "pynids/__init__.py", '__version__ = "2.1.0"\n', "Bump")
    (local / "pynids/__init__.py").write_text('__version__ = "mine"\n')
    upd = Updater(repo=local, on_restart=lambda: None)
    info = upd.check()
    assert info["available"] and "unsaved edits" in info["blocked"]
    upd.apply()
    info = wait(upd, "error")
    assert "unsaved edits" in info["error"]
    assert (local / "pynids/__init__.py").read_text() == '__version__ = "mine"\n'


def test_unrelated_uncommitted_edit_is_kept(repos):
    local, up = repos
    push(up, "pynids/__init__.py", '__version__ = "2.1.0"\n', "Bump")
    (local / "pyproject.toml").write_text("[project]\n# local tweak\n")
    restarted = threading.Event()
    upd = Updater(repo=local, on_restart=restarted.set)
    upd.apply()
    assert restarted.wait(30), upd.status()
    assert "local tweak" in (local / "pyproject.toml").read_text()


def test_local_commits_block(repos):
    local, up = repos
    push(up, "a.txt", "a", "upstream change")
    commit(local, "b.txt", "b", "local change")
    info = Updater(repo=local).check()
    assert info["available"] and "local commit" in info["blocked"]


def test_failed_verification_rolls_back(repos, tmp_path):
    local, up = repos
    push(up, "a.txt", "a", "upstream change")
    before = git(local, "rev-parse", "HEAD")
    broken = tmp_path / "python"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)
    upd = Updater(repo=local, python=str(broken), on_restart=lambda: None)
    upd.apply()
    info = wait(upd, "error")
    assert "previous version was restored" in info["error"]
    assert git(local, "rev-parse", "HEAD") == before


def test_without_launchd_asks_for_restart(repos):
    local, up = repos
    push(up, "a.txt", "a", "upstream change")
    upd = Updater(repo=local, on_restart=None)
    upd.apply()
    assert wait(upd, "restart-needed")["available"] is False


def test_not_a_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr("pynids.service.updater.default_repo", lambda: None)
    upd = Updater()
    assert upd.status()["supported"] is False
    with pytest.raises(UpdateError):
        upd.apply()


def test_apply_when_up_to_date_releases_the_lock(repos):
    local, _ = repos
    upd = Updater(repo=local)
    upd.apply()
    wait(upd, "idle")
    # A second check must actually run, not report "already running" forever.
    assert upd._lock.acquire(blocking=False)
    upd._lock.release()
