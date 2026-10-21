"""
In-app updates from GitHub.

PyNIDS runs from a git checkout (``pip install -e``), so "updating" means
fast-forwarding that checkout to the latest commit on GitHub and restarting.
The daemon does it so the dashboard and menu bar app can offer a one-click
**Update** button without a terminal:

1. **Check** — fetch the current branch from the public HTTPS URL of
   ``origin`` (no SSH keys or credentials needed) and count new commits.
2. **Apply** — ``git merge --ff-only``, ``pip install -e .[all]`` when
   ``pyproject.toml`` changed, then import the new code in a fresh
   interpreter.  Any failure rolls the checkout back (``git reset --keep``,
   which never touches uncommitted edits).
3. **Restart** — the daemon exits with code 75 and launchd starts the new
   version a few seconds later.  The menu bar app notices that its own
   sources (``macos/``) changed and rebuilds itself.

The daemon runs as root, but the checkout belongs to the user who cloned
it, so every git / pip command runs as that user: no root-owned files end
up in the repo or the virtualenv.

Only fast-forwards are applied.  A checkout with local commits, or with
uncommitted edits to files the update changes, is left alone and the
reason is shown instead.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import __version__

logger = logging.getLogger(__name__)

_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
_VERSION_RE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


class UpdateError(RuntimeError):
    pass


def default_repo() -> Optional[Path]:
    """The git checkout this copy of PyNIDS runs from, if any."""
    root = Path(__file__).resolve().parents[2]
    return root if (root / ".git").exists() and (root / "pyproject.toml").exists() else None


def https_url(url: str) -> str:
    """``git@github.com:owner/repo.git`` → ``https://github.com/owner/repo.git``."""
    url = url.strip()
    m = re.fullmatch(r"(?:ssh://)?git@([^:/]+)[:/](.+)", url)
    if m:
        return f"https://{m.group(1)}/{m.group(2)}"
    return url


class Updater:
    def __init__(
        self,
        repo: Optional[Path] = None,
        python: Optional[str] = None,
        state_file: Optional[Path] = None,
        on_restart: Optional[Callable[[], None]] = None,
        broadcast: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        interval_hours: float = 6,
        extras: str = "all",
    ) -> None:
        self.repo = Path(repo) if repo else default_repo()
        self.python = python or sys.executable
        self.state_file = state_file
        self.on_restart = on_restart
        self.broadcast = broadcast or (lambda kind, data: None)
        self.interval = max(0.0, float(interval_hours)) * 3600
        self.extras = extras
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._info: Dict[str, Any] = {
            "supported": self.repo is not None,
            "state": "idle",
            "available": False,
            "current_version": __version__,
        }
        if self.repo is None:
            self._info["error"] = "This copy of PyNIDS wasn't installed from a git checkout."

    # --- running commands as the checkout's owner ---------------------------

    def _owner_kwargs(self) -> Dict[str, Any]:
        env = {"PATH": _SAFE_PATH, "GIT_TERMINAL_PROMPT": "0", "LANG": "en_US.UTF-8",
               "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        kw: Dict[str, Any] = {}
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            import pwd

            st = self.repo.stat()
            pw = pwd.getpwuid(st.st_uid)
            env.update(HOME=pw.pw_dir, USER=pw.pw_name, LOGNAME=pw.pw_name)
            kw.update(user=st.st_uid, group=st.st_gid,
                      extra_groups=os.getgrouplist(pw.pw_name, st.st_gid))
        else:
            env["HOME"] = os.environ.get("HOME", str(Path.home()))
        kw["env"] = env
        return kw

    def _run(self, *args: str, timeout: float = 120, check: bool = True) -> str:
        proc = subprocess.run(list(args), cwd=str(self.repo), capture_output=True, text=True,
                              timeout=timeout, check=False, **self._owner_kwargs())
        if check and proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip().splitlines()
            raise UpdateError(msg[-1] if msg else f"{args[0]} exited with {proc.returncode}")
        return proc.stdout.strip()

    def _git(self, *args: str, timeout: float = 60, check: bool = True) -> str:
        return self._run("git", *args, timeout=timeout, check=check)

    # --- status --------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        info = dict(self._info)
        info["last_update"] = self._last_update()
        if self.repo is not None:
            try:
                info["app_tree"] = self._git("rev-parse", "HEAD:macos", timeout=10)
                info["repo"] = str(self.repo)
            except (UpdateError, OSError, subprocess.SubprocessError):
                pass
        return info

    def brief(self) -> Dict[str, Any]:
        """Small subset folded into /api/summary for the header / menu bar."""
        i = self._info
        return {k: i.get(k) for k in ("supported", "state", "available", "latest_version",
                                      "behind", "step", "error", "blocked")}

    def _set(self, **kw: Any) -> None:
        self._info.update(kw)
        self.broadcast("update", self.brief())

    def _last_update(self) -> Optional[Dict[str, Any]]:
        if not self.state_file:
            return None
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    # --- check ---------------------------------------------------------------

    def check(self) -> Dict[str, Any]:
        if self.repo is None:
            return self.status()
        if not self._lock.acquire(blocking=False):
            return self.status()  # a check or update is already running
        try:
            self._set(state="checking", error=None)
            self._check_locked()
            self._set(state="idle")
        except Exception as exc:  # noqa: BLE001 — report it; never leave state "checking"
            logger.warning("Update check failed: %s", exc)
            self._set(state="idle", error=f"Couldn't check for updates: {exc}")
        finally:
            self._lock.release()
        return self.status()

    def _check_locked(self) -> None:
        branch = self._git("symbolic-ref", "--short", "-q", "HEAD", check=False)
        if not branch:
            raise UpdateError("the checkout is not on a branch")
        url = https_url(self._git("remote", "get-url", "origin"))
        tracking = f"refs/remotes/origin/{branch}"
        self._git("fetch", "--quiet", "--no-tags", url, f"+refs/heads/{branch}:{tracking}", timeout=90)
        head = self._git("rev-parse", "HEAD")
        latest = self._git("rev-parse", tracking)
        behind = int(self._git("rev-list", "--count", f"HEAD..{tracking}") or 0)
        ahead = int(self._git("rev-list", "--count", f"{tracking}..HEAD") or 0)
        commits: List[Dict[str, Any]] = []
        for line in self._git("log", "-n", "20", "--format=%h%x1f%s%x1f%ct", f"HEAD..{tracking}").splitlines():
            parts = line.split("\x1f")
            if len(parts) == 3:
                commits.append({"sha": parts[0], "subject": parts[1], "time": int(parts[2])})
        m = _VERSION_RE.search(self._git("show", f"{tracking}:pynids/__init__.py", check=False))

        blocked = None
        if behind and ahead:
            blocked = (f"This copy has {ahead} local commit{'s' if ahead > 1 else ''} that aren't on "
                       "GitHub, so it can't be updated automatically. Use git in a terminal.")
        elif behind:
            changed = set(self._git("diff", "--name-only", "HEAD", tracking).splitlines())
            dirty = set(self._git("diff", "--name-only", "HEAD").splitlines())  # staged + unstaged
            clash = sorted(changed & dirty)
            if clash:
                blocked = ("You have unsaved edits to files this update changes: "
                           + ", ".join(clash[:5]) + (" …" if len(clash) > 5 else "")
                           + ". Commit or discard them, then update.")
        self._info.update(
            branch=branch, remote=url, current_commit=head[:7], latest_commit=latest[:7],
            latest_version=m.group(1) if m else None, behind=behind, ahead=ahead,
            commits=commits, available=behind > 0, blocked=blocked, checked_at=time.time(),
        )

    # --- apply ---------------------------------------------------------------

    def apply(self) -> Dict[str, Any]:
        """Start the update in the background; poll status() for progress."""
        if self.repo is None:
            raise UpdateError(self._info.get("error") or "updates are unavailable")
        if not self._lock.acquire(blocking=False):
            raise UpdateError("An update check or install is already running.")
        self._set(state="updating", step="Checking GitHub…", error=None)
        threading.Thread(target=self._apply_locked, name="update", daemon=True).start()
        return self.status()

    def _apply_locked(self) -> None:
        old = None
        try:
            self._check_locked()
            if not self._info.get("behind"):
                self._set(state="idle", step=None, available=False)
                self._lock.release()
                return
            if self._info.get("blocked"):
                raise UpdateError(self._info["blocked"])
            old = self._git("rev-parse", "HEAD")
            target = f"refs/remotes/origin/{self._info['branch']}"

            self._set(step="Downloading the new version…")
            self._git("merge", "--ff-only", "--quiet", target)
            new = self._git("rev-parse", "HEAD")
            changed = set(self._git("diff", "--name-only", old, new).splitlines())

            if "pyproject.toml" in changed:
                self._set(step="Installing new dependencies…")
                spec = f".[{self.extras}]" if self.extras else "."
                self._run(self.python, "-m", "pip", "install", "--quiet", "-e", spec, timeout=900)

            self._set(step="Verifying the new version…")
            self._run(self.python, "-I", "-c", "import pynids.cli, pynids.service.daemon", timeout=120)
        except Exception as exc:  # noqa: BLE001 — roll back and release the lock on anything
            logger.error("Update failed: %s", exc)
            rolled = ""
            if old:
                try:
                    self._git("reset", "--keep", "--quiet", old)
                    rolled = " The previous version was restored."
                except (UpdateError, OSError, subprocess.SubprocessError) as rb:
                    logger.error("Rollback failed: %s", rb)
                    rolled = " Rolling back failed too; run `git status` in the PyNIDS folder."
            self._set(state="error", step=None, error=f"Update failed: {exc}.{rolled}")
            self._lock.release()
            return

        record = {"from": old[:7], "to": new[:7], "at": time.time(),
                  "version": self._info.get("latest_version"), "app_changed": any(
                      p.startswith("macos/") or p == "pyproject.toml" for p in changed)}
        if self.state_file:
            try:
                self.state_file.write_text(json.dumps(record), encoding="utf-8")
                os.chmod(self.state_file, 0o644)
            except OSError as exc:
                logger.debug("could not record update: %s", exc)
        logger.warning("Updated %s → %s; restarting", old[:7], new[:7])
        self._info.update(available=False, behind=0, commits=[], current_commit=new[:7])
        if self.on_restart is None:
            self._set(state="restart-needed", step="Restart PyNIDS to finish updating.")
            self._lock.release()
            return
        self._set(state="restarting", step="Restarting PyNIDS…")
        # Give the API a moment to report "restarting" before we go away.
        time.sleep(1.5)
        self.on_restart()

    # --- background checks ---------------------------------------------------

    def start(self, initial_delay: float = 60) -> None:
        if self.repo is None or self.interval <= 0:
            return
        threading.Thread(target=self._loop, args=(initial_delay,), name="update-check", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self, delay: float) -> None:
        if self._stop.wait(delay):
            return
        while True:
            self.check()
            if self._stop.wait(self.interval):
                return
