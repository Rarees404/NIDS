"""
Active response: block IPs with macOS's built-in ``pf`` packet filter.

This turns detection into prevention.  It is **off by default** and every
path has guard rails, because a bad block can cut the machine off the
network.

How it hooks into pf
--------------------
The stock ``/etc/pf.conf`` on macOS evaluates ``anchor "com.apple/*"``, so
rules loaded into the sub-anchor ``com.apple/250.PyNIDS`` are active without
editing any system file.  The anchor holds a single persistent table::

    table <pynids_block> persist
    block drop quick from <pynids_block> to any
    block drop quick from any to <pynids_block>

Adding or removing an IP is then just a table operation, and flushing the
anchor removes every PyNIDS rule at once.

Guard rails
-----------
* Loopback, private (RFC 1918 / ULA), link-local, multicast, and reserved
  addresses are never blocked.
* The default gateway and the configured DNS servers are never blocked.
* An explicit ``never_block`` allowlist (IPs or CIDRs) is honoured.
* Every block has an expiry (default 1 hour); expired blocks are lifted
  automatically.
* ``dry_run`` records decisions without touching pf.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from ..alerts.manager import BaseOutput
from ..alerts.model import Alert, AlertType, Severity
from ..paths import blocklist_path

logger = logging.getLogger(__name__)

ANCHOR = "com.apple/250.PyNIDS"
TABLE = "pynids_block"
PFCTL = "/sbin/pfctl"

_RULES = f"""table <{TABLE}> persist
block drop quick from <{TABLE}> to any
block drop quick from any to <{TABLE}>
"""

Runner = Callable[[Sequence[str], Optional[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(args: Sequence[str], stdin: Optional[str] = None):
    return subprocess.run(
        list(args), input=stdin, capture_output=True, text=True, timeout=15, check=False
    )


@dataclass
class BlockEntry:
    ip: str
    reason: str
    created: float
    expires: Optional[float]
    source: str = "manual"  # "manual" | "auto"
    alert_id: Optional[str] = None


class BlockRefused(ValueError):
    """Raised when an IP is protected by a guard rail."""


class PfBlocker:
    """
    Manage the PyNIDS pf table and a JSON ledger of why each IP is blocked.

    Args:
        ledger_path: Where block reasons and expiries are persisted.
        never_block: Extra IPs / CIDRs that must never be blocked.
        dry_run:     Record decisions but never call pfctl.
        runner:      Injectable subprocess runner (tests).
    """

    def __init__(
        self,
        ledger_path: Optional[Path] = None,
        never_block: Iterable[str] = (),
        dry_run: bool = False,
        runner: Runner = _default_runner,
    ) -> None:
        self.ledger_path = Path(ledger_path) if ledger_path else blocklist_path()
        self.dry_run = dry_run
        self._run = runner
        self._lock = threading.Lock()
        self._entries: Dict[str, BlockEntry] = {}
        self._anchor_loaded = False
        self._never: List[ipaddress._BaseNetwork] = []
        for item in never_block:
            try:
                self._never.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                logger.warning("Ignoring invalid never_block entry %r", item)
        self._protected_ips = set(_system_critical_ips())
        self._load_ledger()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_blockable(self, ip: str) -> None:
        """Raise :class:`BlockRefused` if *ip* is protected by a guard rail."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise BlockRefused(f"{ip!r} is not a valid IP address") from None
        if not addr.is_global or addr.is_multicast:
            raise BlockRefused(f"{ip} is a local/private/reserved address — never blocked")
        if ip in self._protected_ips:
            raise BlockRefused(f"{ip} is your gateway or DNS server — never blocked")
        for net in self._never:
            if addr.version == net.version and addr in net:
                raise BlockRefused(f"{ip} is on the never_block allowlist ({net})")

    def block(
        self,
        ip: str,
        reason: str,
        ttl: Optional[float] = 3600.0,
        source: str = "manual",
        alert_id: Optional[str] = None,
    ) -> BlockEntry:
        self.check_blockable(ip)
        now = time.time()
        entry = BlockEntry(
            ip=ip, reason=reason, created=now,
            expires=(now + ttl) if ttl else None, source=source, alert_id=alert_id,
        )
        with self._lock:
            if not self.dry_run:
                self._ensure_anchor()
                self._pfctl("-a", ANCHOR, "-t", TABLE, "-T", "add", ip)
                # Kill established states so the block takes effect immediately.
                any_net = "::/0" if ":" in ip else "0.0.0.0/0"
                self._pfctl("-k", any_net, "-k", ip, check=False)
                self._pfctl("-k", ip, check=False)
            self._entries[ip] = entry
            self._save_ledger()
        logger.warning("Blocked %s (%s)%s", ip, reason, " [dry-run]" if self.dry_run else "")
        return entry

    def unblock(self, ip: str) -> bool:
        with self._lock:
            existed = self._entries.pop(ip, None) is not None
            if not self.dry_run:
                self._pfctl("-a", ANCHOR, "-t", TABLE, "-T", "delete", ip, check=False)
            self._save_ledger()
        return existed

    def flush(self) -> int:
        """Remove every PyNIDS block and the anchor's rules."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            if not self.dry_run:
                self._pfctl("-a", ANCHOR, "-t", TABLE, "-T", "flush", check=False)
                self._pfctl("-a", ANCHOR, "-F", "rules", check=False)
                self._anchor_loaded = False
            self._save_ledger()
        return count

    def list(self) -> List[BlockEntry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.created, reverse=True)

    def expire(self) -> List[str]:
        """Lift blocks whose expiry has passed.  Returns the IPs unblocked."""
        now = time.time()
        with self._lock:
            due = [ip for ip, e in self._entries.items() if e.expires and e.expires <= now]
        for ip in due:
            self.unblock(ip)
        return due

    def sync(self) -> None:
        """Re-apply the ledger to pf (after a reboot or pf flush)."""
        self.expire()
        with self._lock:
            if self.dry_run or not self._entries:
                return
            self._ensure_anchor()
            self._pfctl("-a", ANCHOR, "-t", TABLE, "-T", "replace", *self._entries.keys())

    def is_blocked(self, ip: str) -> bool:
        return ip in self._entries

    # ------------------------------------------------------------------
    # pf plumbing
    # ------------------------------------------------------------------

    def _ensure_anchor(self) -> None:
        if self._anchor_loaded:
            return
        self._pfctl("-a", ANCHOR, "-f", "-", stdin=_RULES)
        # Enable pf if it is not already running.  "-E" takes a reference
        # that keeps pf enabled; it is harmless if pf is already on.
        status = self._pfctl("-s", "info", check=False)
        if "Status: Enabled" not in (status.stdout or ""):
            self._pfctl("-E", check=False)
        self._anchor_loaded = True

    def _pfctl(self, *args: str, stdin: Optional[str] = None, check: bool = True):
        result = self._run([PFCTL, *args], stdin)
        if check and result.returncode != 0:
            raise RuntimeError(
                f"pfctl {' '.join(args)} failed: {(result.stderr or '').strip()}"
            )
        return result

    # ------------------------------------------------------------------
    # Ledger persistence
    # ------------------------------------------------------------------

    def _load_ledger(self) -> None:
        try:
            data = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            for item in data.get("blocks", []):
                self._entries[item["ip"]] = BlockEntry(**item)
        except (OSError, ValueError, TypeError, KeyError):
            pass

    def _save_ledger(self) -> None:
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.ledger_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"blocks": [asdict(e) for e in self._entries.values()]}, indent=2),
                encoding="utf-8",
            )
            tmp.replace(self.ledger_path)
        except OSError as exc:
            logger.error("Could not save blocklist ledger: %s", exc)


def _system_critical_ips() -> List[str]:
    """Default gateway(s) and configured DNS servers — never block these."""
    ips: List[str] = []
    for family in ("-inet", "-inet6"):
        try:
            out = subprocess.run(
                ["/sbin/route", "-n", "get", family, "default"],
                capture_output=True, text=True, timeout=5, check=False,
            ).stdout
            m = re.search(r"gateway:\s*(\S+)", out)
            if m:
                ips.append(m.group(1).split("%")[0])
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        out = subprocess.run(
            ["/usr/sbin/scutil", "--dns"], capture_output=True, text=True, timeout=5, check=False
        ).stdout
        ips.extend(m.split("%")[0] for m in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out))
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            ips.extend(line.split()[1] for line in f if line.startswith("nameserver"))
    except OSError:
        pass
    return ips


# ---------------------------------------------------------------------------
# Auto-block policy (an alert output)
# ---------------------------------------------------------------------------

class AutoBlockPolicy(BaseOutput):
    """
    Alert output that blocks the remote IP of qualifying alerts.

    Only alerts with a definite malicious verdict qualify by default —
    threat-intel matches and correlated multi-vector attacks — and only at
    or above ``min_severity``.  Behavioural/privacy alerts (trackers,
    WebRTC, QUIC …) never trigger a block.
    """

    def __init__(
        self,
        blocker: PfBlocker,
        min_severity: Severity = Severity.CRITICAL,
        alert_types: Iterable[str] = ("threat_intel", "correlation"),
        ttl: float = 3600.0,
        on_block: Optional[Callable[[BlockEntry, Alert], None]] = None,
    ) -> None:
        self.blocker = blocker
        self.min_severity = min_severity
        self.alert_types = {AlertType(t) for t in alert_types}
        self.ttl = ttl
        self.on_block = on_block

    def emit(self, alert: Alert) -> None:
        if alert.alert_type not in self.alert_types or alert.severity < self.min_severity:
            return
        remote = alert.context.get("remote_ip") or alert.dst_ip
        if alert.context.get("direction") == "inbound" or alert.alert_type == AlertType.CORRELATION:
            remote = alert.src_ip
        if not remote or self.blocker.is_blocked(remote):
            return
        try:
            entry = self.blocker.block(
                remote, reason=alert.message, ttl=self.ttl,
                source="auto", alert_id=alert.alert_id,
            )
        except BlockRefused as exc:
            logger.info("Auto-block skipped: %s", exc)
            return
        except Exception as exc:  # noqa: BLE001
            logger.error("Auto-block of %s failed: %s", remote, exc)
            return
        if self.on_block:
            self.on_block(entry, alert)
