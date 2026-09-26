"""
Per-connection process attribution — "which app made this connection?"

A packet only carries addresses and ports.  To name the application we
periodically snapshot the kernel's socket table (via psutil) and index it
by ``(transport, local port)``.  Packet lookups are then a dict access,
so attribution adds almost nothing to per-packet cost.

Notes
-----
* The snapshot runs on a background thread (default every 1.5 s).
  Mappings are remembered for a few minutes after the socket closes, so
  short connections that close between snapshots are still attributed
  when later packets or alerts refer to them.  The very first packet of a
  brand-new connection can occasionally miss.
* Full attribution needs root (the daemon and ``sudo pynids xray``).
  Without root, psutil can only see the current user's processes, which
  still covers browsers and most apps.
* On macOS, helper processes are folded into their parent app bundle:
  ``Google Chrome Helper (Renderer)`` is reported as ``Google Chrome``.
* Safari, WhatsApp, and other apps built on Network.framework can run
  connections on Apple's user-space network stack.  Those flows are not
  BSD sockets, so psutil/lsof cannot see them; on macOS the snapshot also
  reads ``nettop``, which reports every flow, to attribute them.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple

try:
    import psutil
except ImportError:  # pragma: no cover — psutil is a hard dependency
    psutil = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

ProcInfo = Dict[str, Any]


def app_name_from_exe(exe: Optional[str], fallback: str) -> str:
    """
    Derive a human-friendly application name from an executable path.

    ``/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/...``
    → ``Slack`` (the *outermost* ``.app`` bundle wins).
    """
    # Safari and every WKWebView do their networking in a shared WebKit XPC service.
    if fallback.startswith("com.apple.WebKit"):
        return "Safari / WebKit"
    if exe:
        marker = exe.find(".app/")
        if marker != -1:
            start = exe.rfind("/", 0, marker) + 1
            return exe[start:marker]
        if exe.endswith(".app"):
            return os.path.basename(exe)[:-4]
        # Versioned binaries (".../claude/versions/2.1.0") — use the tool's dir.
        if not any(ch.isalpha() for ch in fallback):
            for part in reversed(exe.split("/")[:-1]):
                if any(ch.isalpha() for ch in part) and part not in ("versions", "bin", "libexec"):
                    return part
    return fallback


class ProcessResolver:
    """
    Map (protocol, local port) → process details.

    Args:
        refresh_interval: Seconds between socket-table snapshots.
        memory_seconds:   How long a mapping survives after its socket closes.
        snapshot:         Injectable snapshot function (tests).
    """

    def __init__(
        self,
        refresh_interval: float = 1.5,
        memory_seconds: float = 300.0,
        snapshot=None,
    ) -> None:
        self.refresh_interval = refresh_interval
        self.memory_seconds = memory_seconds
        self._snapshot = snapshot or self._psutil_snapshot
        self._table: Dict[Tuple[str, int], Tuple[float, ProcInfo]] = {}
        self._proc_cache: Dict[Tuple[int, float], ProcInfo] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.available = psutil is not None or snapshot is not None
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "ProcessResolver":
        if not self.available or self._thread:
            return self
        self.refresh()
        self._thread = threading.Thread(target=self._run, name="proc-resolver", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self.refresh_interval):
            self.refresh()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, proto: Optional[str], port: Optional[int]) -> Optional[ProcInfo]:
        if not proto or not port:
            return None
        with self._lock:
            hit = self._table.get((proto, int(port)))
        return hit[1] if hit else None

    def lookup_packet(self, meta: Dict[str, Any], local_ips: frozenset) -> Optional[ProcInfo]:
        """Attribute a packet to the process owning its local endpoint."""
        proto = meta.get("protocol")
        if proto not in ("tcp", "udp"):
            return None
        src, dst = meta.get("src_ip"), meta.get("dst_ip")
        # Outbound (or loopback): the initiator is the source side.
        if src in local_ips or _is_loopback(src):
            info = self.lookup(proto, meta.get("src_port"))
            if info or not (dst in local_ips or _is_loopback(dst)):
                return info
        return self.lookup(proto, meta.get("dst_port"))

    # ------------------------------------------------------------------
    # Snapshotting
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        now = time.time()
        try:
            rows = self._snapshot()
            self.last_error = None
        except Exception as exc:  # noqa: BLE001 — keep the resolver alive
            self.last_error = str(exc)
            logger.debug("Process snapshot failed: %s", exc)
            return
        with self._lock:
            for proto, port, info in rows:
                self._table[(proto, port)] = (now, info)
            cutoff = now - self.memory_seconds
            stale = [k for k, (ts, _) in self._table.items() if ts < cutoff]
            for k in stale:
                del self._table[k]

    def _psutil_snapshot(self):
        """Yield (proto, local_port, info) for every inet socket we can see."""
        try:
            conns = [(c, c.pid) for c in psutil.net_connections(kind="inet")]
        except psutil.AccessDenied:
            # Not root: fall back to the processes this user owns.
            conns = []
            for proc in psutil.process_iter():
                try:
                    conns.extend((c, proc.pid) for c in proc.net_connections(kind="inet"))
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        rows = []
        for c, pid in conns:
            if not pid or not c.laddr:
                continue
            proto = "tcp" if c.type == _SOCK_STREAM else "udp"
            info = self._proc_info(pid)
            if info:
                rows.append((proto, c.laddr.port, info))
        if sys.platform == "darwin":
            for proto, port, pid, name in nettop_flows():
                info = self._proc_info(pid) or {
                    "pid": pid, "process": name, "app": app_name_from_exe("", name),
                    "exe": "", "user": "",
                }
                rows.append((proto, port, info))
        return rows

    def _proc_info(self, pid: int) -> Optional[ProcInfo]:
        try:
            proc = psutil.Process(pid)
            key = (pid, proc.create_time())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        cached = self._proc_cache.get(key)
        if cached:
            return cached
        try:
            name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        try:
            exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            exe = ""
        try:
            user = proc.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
            user = ""
        info = {
            "pid": pid,
            "process": name,
            "app": app_name_from_exe(exe, name),
            "exe": exe,
            "user": user,
        }
        if len(self._proc_cache) > 4096:
            self._proc_cache.clear()
        self._proc_cache[key] = info
        return info

    @property
    def size(self) -> int:
        return len(self._table)


_SOCK_STREAM = 1

_NETTOP = "/usr/bin/nettop"


def parse_nettop(output: str):
    """
    Parse ``nettop -L 1 -n -x -J bytes_in`` CSV into (proto, local_port, pid, name).

    Process rows look like ``com.apple.WebKit.Networking.933,4521,`` and are
    followed by their flows, e.g. ``quic4 10.0.0.5:52800<->157.240.253.60:443,49,``
    or ``tcp6 fe80::1%en0.51750<->*.*,,``.
    """
    rows = []
    pid: Optional[int] = None
    name = ""
    for line in output.splitlines():
        head = line.split(",", 1)[0].strip()
        if not head:
            continue
        kind = head.split(" ", 1)[0]
        if kind[:3] in ("tcp", "udp") or kind[:4] == "quic":
            if pid is None or "<->" not in head:
                continue
            local = head.split(" ", 1)[1].split("<->", 1)[0]
            sep = ":" if kind.endswith("4") else "."
            port_text = local.rsplit(sep, 1)[-1]
            if not port_text.isdigit():
                continue
            proto = "tcp" if kind.startswith("tcp") else "udp"
            rows.append((proto, int(port_text), pid, name))
        else:
            base, _, pid_text = head.rpartition(".")
            if pid_text.isdigit() and base:
                pid, name = int(pid_text), base
            else:
                pid = None
    return rows


def nettop_flows():
    """Every flow on the machine, including Network.framework's user-space ones."""
    try:
        out = subprocess.run(
            [_NETTOP, "-L", "1", "-n", "-x", "-J", "bytes_in"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_nettop(out)


def _is_loopback(ip: Optional[str]) -> bool:
    return bool(ip) and (ip.startswith("127.") or ip == "::1")


def local_addresses() -> frozenset:
    """All IP addresses assigned to this machine's interfaces."""
    addrs = {"127.0.0.1", "::1"}
    if psutil is None:
        return frozenset(addrs)
    try:
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family.name in ("AF_INET", "AF_INET6") and entry.address:
                    addrs.add(entry.address.split("%")[0])
    except Exception:  # noqa: BLE001
        pass
    return frozenset(addrs)
