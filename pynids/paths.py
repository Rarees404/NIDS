"""
Filesystem locations shared by the daemon, the CLI, and the macOS apps.

The background daemon runs as root under launchd, while the CLI, the
menu bar app, and the widget run as the logged-in user.  They all need to
agree on where the database, threat-intel cache, and API token live, so
every path is resolved here.

Resolution order for the data directory:

1. ``$PYNIDS_HOME`` if set.
2. ``/Library/Application Support/PyNIDS`` on macOS when running as root
   (the daemon), or when that directory already exists (a user process
   reading the daemon's data).
3. ``~/Library/Application Support/PyNIDS`` on macOS, ``~/.local/share/pynids``
   elsewhere.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

SYSTEM_DIR = Path("/Library/Application Support/PyNIDS")
LOG_DIR = Path("/Library/Logs/PyNIDS")

DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8787


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def data_dir() -> Path:
    """Return (and create, when permitted) the PyNIDS data directory."""
    env = os.environ.get("PYNIDS_HOME")
    if env:
        path = Path(env).expanduser()
    elif sys.platform == "darwin" and (is_root() or SYSTEM_DIR.exists()):
        path = SYSTEM_DIR
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "PyNIDS"
    else:
        path = Path.home() / ".local" / "share" / "pynids"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass
    return path


def db_path() -> Path:
    return data_dir() / "events.db"


def intel_dir() -> Path:
    path = data_dir() / "intel"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass
    return path


def geoip_dir() -> Path:
    path = data_dir() / "geoip"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass
    return path


def token_path() -> Path:
    return data_dir() / "api-token"


def blocklist_path() -> Path:
    return data_dir() / "blocklist.json"


def anthropic_key_path() -> Path:
    return data_dir() / "anthropic-key"


def daemon_config_path() -> Path:
    return data_dir() / "config.yaml"


def read_api_token() -> str:
    """Return the API token the daemon wrote, or '' if it is not readable."""
    try:
        return token_path().read_text(encoding="utf-8").strip()
    except OSError:
        return ""
