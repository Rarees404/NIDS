"""
Install / remove the PyNIDS daemon as a macOS LaunchDaemon.

The plist runs ``<this python> -m pynids daemon run`` as root at boot,
keeps it alive (launchd restarts it on crash or network change), and logs
to ``/Library/Logs/PyNIDS/daemon.log``.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from ..paths import LOG_DIR, SYSTEM_DIR

LABEL = "com.pynids.daemon"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
LOG_FILE = LOG_DIR / "daemon.log"


def build_plist(
    python: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    working_dir: Optional[str] = None,
) -> bytes:
    args = [python or sys.executable, "-m", "pynids", "daemon", "run"] + list(extra_args or [])
    plist = {
        "Label": LABEL,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "ProcessType": "Interactive",
        "StandardOutPath": str(LOG_FILE),
        "StandardErrorPath": str(LOG_FILE),
        "WorkingDirectory": working_dir or str(SYSTEM_DIR),
        "EnvironmentVariables": {
            "PYNIDS_HOME": str(SYSTEM_DIR),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        },
    }
    return plistlib.dumps(plist)


def _launchctl(*args: str) -> Tuple[int, str]:
    proc = subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def install(extra_args: Optional[List[str]] = None, working_dir: Optional[str] = None) -> str:
    if os.geteuid() != 0:
        raise PermissionError("Installing the daemon needs root: sudo pynids daemon install")
    SYSTEM_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if PLIST_PATH.exists():
        _launchctl("bootout", f"system/{LABEL}")
    PLIST_PATH.write_bytes(build_plist(extra_args=extra_args, working_dir=working_dir))
    os.chmod(PLIST_PATH, 0o644)
    os.chown(PLIST_PATH, 0, 0)
    code, out = _launchctl("bootstrap", "system", str(PLIST_PATH))
    if code != 0:
        raise RuntimeError(f"launchctl bootstrap failed: {out}")
    return str(PLIST_PATH)


def uninstall() -> bool:
    if os.geteuid() != 0:
        raise PermissionError("Removing the daemon needs root: sudo pynids daemon uninstall")
    existed = PLIST_PATH.exists()
    _launchctl("bootout", f"system/{LABEL}")
    if existed:
        PLIST_PATH.unlink()
    return existed


def restart() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Restarting the daemon needs root: sudo pynids daemon restart")
    code, out = _launchctl("kickstart", "-k", f"system/{LABEL}")
    if code != 0:
        raise RuntimeError(f"launchctl kickstart failed: {out}")


def is_installed() -> bool:
    return PLIST_PATH.exists()


def launchd_state() -> Optional[str]:
    code, out = _launchctl("print", f"system/{LABEL}")
    if code != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("state ="):
            return line.split("=", 1)[1].strip()
    return "loaded"
