"""
Persistence: which programs macOS starts automatically, and from where.

Malware that wants to survive a reboot almost always installs a launchd
job: a property list in one of the LaunchAgents / LaunchDaemons folders
that points at its binary.  When PyNIDS flags a suspicious process, the
first cleanup question is "what keeps starting it?"; :func:`scan` answers
it by reading every job and indexing them by the program they run.

Background Task Management (``sfltool dumpbtm``) also tracks login items,
but needs extra privileges and its format changes between releases, so the
plist folders remain the dependable source.
"""
from __future__ import annotations

import glob
import os
import plistlib
import time
from typing import Any, Dict, List, Optional

SYSTEM_FOLDERS = (
    ("/Library/LaunchDaemons", "daemon", "all users, runs as root"),
    ("/Library/LaunchAgents", "agent", "every user, at login"),
)
APPLE_FOLDERS = (
    ("/System/Library/LaunchDaemons", "daemon", "macOS"),
    ("/System/Library/LaunchAgents", "agent", "macOS"),
)


def _user_folders() -> List[tuple]:
    out = []
    for home in sorted(glob.glob("/Users/*")):
        path = os.path.join(home, "Library", "LaunchAgents")
        if os.path.isdir(path):
            out.append((path, "agent", f"user {os.path.basename(home)}, at login"))
    return out


def parse_job(path: str, data: Dict[str, Any]) -> Dict[str, Any]:
    args = data.get("ProgramArguments") or []
    program = data.get("Program") or (args[0] if args else None)
    return {
        "label": data.get("Label") or os.path.basename(path)[:-6],
        "plist": path,
        "program": program,
        "arguments": [str(a) for a in args[1:8]],
        "run_at_load": bool(data.get("RunAtLoad")),
        "keep_alive": bool(data.get("KeepAlive")),
        "interval": data.get("StartInterval"),
        "disabled": bool(data.get("Disabled")),
    }


def scan(include_apple: bool = False, folders: Optional[List[tuple]] = None) -> List[Dict[str, Any]]:
    """Every launchd job PyNIDS can read, newest plist first."""
    if folders is None:
        folders = list(SYSTEM_FOLDERS) + _user_folders() + (list(APPLE_FOLDERS) if include_apple else [])
    jobs: List[Dict[str, Any]] = []
    for folder, kind, scope in folders:
        for path in glob.glob(os.path.join(folder, "*.plist")):
            try:
                with open(path, "rb") as f:
                    data = plistlib.load(f)
                mtime = os.path.getmtime(path)
            except Exception:  # noqa: BLE001 — unreadable or malformed plist
                continue
            if not isinstance(data, dict):
                continue
            job = parse_job(path, data)
            job.update({"kind": kind, "scope": scope, "modified": mtime,
                        "apple": folder.startswith("/System/")})
            jobs.append(job)
    jobs.sort(key=lambda j: -j["modified"])
    return jobs


class PersistenceIndex:
    """Cached :func:`scan`, indexed by program path (rescanned every few minutes)."""

    def __init__(self, ttl: float = 300.0, scanner=scan) -> None:
        self.ttl = ttl
        self._scanner = scanner
        self._jobs: List[Dict[str, Any]] = []
        self._by_program: Dict[str, List[Dict[str, Any]]] = {}
        self._at = 0.0

    def jobs(self, refresh: bool = False) -> List[Dict[str, Any]]:
        if refresh or time.time() - self._at > self.ttl:
            self._jobs = self._scanner()
            index: Dict[str, List[Dict[str, Any]]] = {}
            for job in self._jobs:
                if job.get("program"):
                    index.setdefault(job["program"], []).append(job)
            self._by_program = index
            self._at = time.time()
        return self._jobs

    def for_program(self, exe: Optional[str]) -> List[Dict[str, Any]]:
        """launchd jobs that start *exe* (or the app bundle it belongs to)."""
        if not exe:
            return []
        self.jobs()
        hits = list(self._by_program.get(exe, []))
        bundle = exe.split(".app/", 1)[0] + ".app/" if ".app/" in exe else None
        if bundle:
            for program, jobs in self._by_program.items():
                if program != exe and program.startswith(bundle):
                    hits.extend(jobs)
        return hits
