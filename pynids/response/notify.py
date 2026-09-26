"""
Native macOS notifications for important alerts.

The daemon runs as root, and a root process cannot post to the logged-in
user's Notification Center directly.  We look up the console user and run
``osascript`` inside their GUI session with ``launchctl asuser``, which is
the supported way for a system daemon to talk to the user session.

Notifications are rate-limited and coalesced: a burst of alerts becomes a
single "5 new alerts" banner rather than a wall of popups.
"""
from __future__ import annotations

import logging
import os
import pwd
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, List, Optional, Sequence

from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, Severity

logger = logging.getLogger(__name__)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def console_user() -> Optional[tuple]:
    """Return (username, uid) of the user logged in at the GUI, or None."""
    try:
        st = os.stat("/dev/console")
        if st.st_uid == 0:
            return None
        return pwd.getpwuid(st.st_uid).pw_name, st.st_uid
    except (OSError, KeyError):
        return None


def _default_runner(args: Sequence[str]) -> None:
    subprocess.run(list(args), capture_output=True, timeout=10, check=False)


def post_notification(
    title: str,
    message: str,
    subtitle: str = "",
    sound: bool = False,
    runner: Callable[[Sequence[str]], None] = _default_runner,
) -> bool:
    """Show a macOS notification banner.  Returns False if it could not be posted."""
    if sys.platform != "darwin":
        return False
    script = f'display notification "{_escape(message)}" with title "{_escape(title)}"'
    if subtitle:
        script += f' subtitle "{_escape(subtitle)}"'
    if sound:
        script += ' sound name "Funk"'
    cmd: List[str] = ["/usr/bin/osascript", "-e", script]
    if os.geteuid() == 0:
        user = console_user()
        if not user:
            return False
        name, uid = user
        cmd = ["/bin/launchctl", "asuser", str(uid), "/usr/bin/sudo", "-u", name] + cmd
    try:
        runner(cmd)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Notification failed: %s", exc)
        return False


class NotificationOutput(BaseOutput):
    """
    Alert output that raises a macOS notification for important alerts.

    Args:
        min_severity:  Only alerts at or above this level notify.
        min_interval:  Minimum seconds between banners; alerts arriving
                       inside the window are coalesced into the next one.
        poster:        Injectable notification function (tests).
    """

    def __init__(
        self,
        min_severity: Severity = Severity.HIGH,
        min_interval: float = 15.0,
        poster: Callable[..., bool] = post_notification,
    ) -> None:
        self.min_severity = min_severity
        self.min_interval = min_interval
        self._post = poster
        self._lock = threading.Lock()
        self._last_post = 0.0
        self._pending: List[Alert] = []
        self._timer: Optional[threading.Timer] = None
        self.enabled = True

    def emit(self, alert: Alert) -> None:
        if not self.enabled or alert.severity < self.min_severity:
            return
        with self._lock:
            self._pending.append(alert)
            wait = self.min_interval - (time.monotonic() - self._last_post)
            if wait <= 0:
                self._flush_locked()
            elif self._timer is None:
                self._timer = threading.Timer(wait, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self) -> None:
        with self._lock:
            self._timer = None
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending:
            return
        alerts, self._pending = self._pending, []
        self._last_post = time.monotonic()
        worst = max(alerts, key=lambda a: a.severity.numeric)
        app = worst.context.get("app")
        if len(alerts) == 1:
            title = f"PyNIDS · {worst.severity.value}"
            subtitle = app or (worst.rule_id or worst.alert_type.value)
            message = worst.message
        else:
            title = f"PyNIDS · {len(alerts)} new alerts"
            subtitle = f"Most severe: {worst.severity.value}" + (f" · {app}" if app else "")
            message = worst.message
        threading.Thread(
            target=self._post,
            args=(title, message[:220]),
            kwargs={"subtitle": subtitle, "sound": worst.severity >= Severity.CRITICAL},
            daemon=True,
        ).start()

    def close(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None


def notifications_supported() -> bool:
    return sys.platform == "darwin" and shutil.which("osascript") is not None
