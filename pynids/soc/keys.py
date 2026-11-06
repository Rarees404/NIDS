"""
API keys for the investigation sources (VirusTotal, AbuseIPDB, …).

Stored as JSON in the data directory with ``0600`` permissions, next to the
API token and the Anthropic key.  The macOS Keychain isn't used because the
daemon runs as root under launchd, outside the user's login keychain.

An environment variable ``PYNIDS_KEY_<NAME>`` (e.g. ``PYNIDS_KEY_VIRUSTOTAL``)
overrides the stored value.  Key values never leave this module through the
API: callers only learn whether a key is configured.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Dict, Optional


class KeyStore:
    def __init__(self, path: Optional[Path]) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._mtime = self._stat()
        self._keys: Dict[str, str] = self._load()

    def _stat(self) -> Optional[int]:
        try:
            return self.path.stat().st_mtime_ns if self.path else None
        except OSError:
            return None

    def _refresh(self) -> None:
        """Pick up changes another process (``pynids soc key set`` vs the daemon) saved."""
        mtime = self._stat()
        if mtime != self._mtime:
            self._mtime = mtime
            self._keys = self._load()

    def _load(self) -> Dict[str, str]:
        if not self.path:
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {str(k): str(v) for k, v in data.items() if v} if isinstance(data, dict) else {}

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # mkstemp: a fresh 0600 file every time, never a leftover with older permissions.
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._keys, fh)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._mtime = self._stat()

    def get(self, name: str) -> Optional[str]:
        env = os.environ.get(f"PYNIDS_KEY_{name.upper()}")
        if env:
            return env.strip()
        with self._lock:
            self._refresh()
            return self._keys.get(name)

    def set(self, name: str, value: str) -> None:
        value = (value or "").strip()
        with self._lock:
            self._refresh()
            if value:
                self._keys[name] = value
            else:
                self._keys.pop(name, None)
            self._save()

    def delete(self, name: str) -> bool:
        with self._lock:
            self._refresh()
            existed = self._keys.pop(name, None) is not None
            self._save()
        return existed

    def configured(self, name: str) -> bool:
        return bool(self.get(name))
