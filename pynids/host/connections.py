"""
Live socket table: every connection and listening port on this Mac, with
the program that owns it.  A better ``netstat -anv`` / ``lsof -i``.

Two sources are merged:

* psutil (the kernel's BSD socket table), with full process details;
* ``nettop`` on macOS, for flows on Apple's user-space network stack
  (Safari, WhatsApp, other Network.framework apps), which BSD socket tools
  cannot see at all.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from ..enrich.process import _NETTOP, app_name_from_exe

Row = Dict[str, Any]

_SOCK_STREAM = 1


def _proc_details(pid: Optional[int], cache: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    if not pid:
        return {}
    if pid in cache:
        return cache[pid]
    info: Dict[str, Any] = {"pid": pid}
    try:
        proc = psutil.Process(pid)
        info["process"] = proc.name()
        try:
            info["exe"] = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
            info["exe"] = ""
        try:
            info["user"] = proc.username()
        except (psutil.AccessDenied, KeyError):
            info["user"] = ""
        try:
            info["ppid"] = proc.ppid()
            info["started"] = proc.create_time()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass
        info["app"] = app_name_from_exe(info.get("exe"), info["process"])
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    cache[pid] = info
    return info


def _split_nettop_addr(text: str, v4: bool) -> Tuple[Optional[str], Optional[int]]:
    if text in ("*.*", "*:*", ""):
        return None, None
    sep = ":" if v4 else "."
    host, _, port = text.rpartition(sep)
    host = host.split("%", 1)[0]
    return (None if host in ("*", "") else host), (int(port) if port.isdigit() else None)


def parse_nettop_full(output: str) -> List[Row]:
    """``nettop -L 1 -n -x`` → rows with local *and* remote endpoints."""
    rows: List[Row] = []
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
            local, remote = head.split(" ", 1)[1].split("<->", 1)
            v4 = kind.endswith("4")
            lip, lport = _split_nettop_addr(local, v4)
            rip, rport = _split_nettop_addr(remote, v4)
            rows.append({
                "proto": "tcp" if kind.startswith("tcp") else "udp",
                "transport": "quic" if kind.startswith("quic") else None,
                "local_ip": lip, "local_port": lport, "remote_ip": rip, "remote_port": rport,
                "state": None, "pid": pid, "process": name, "source": "nettop",
            })
        else:
            base, _, pid_text = head.rpartition(".")
            if pid_text.isdigit() and base:
                pid, name = int(pid_text), base
            else:
                pid = None
    return rows


def _nettop_rows() -> List[Row]:
    if sys.platform != "darwin":
        return []
    try:
        out = subprocess.run([_NETTOP, "-L", "1", "-n", "-x", "-J", "bytes_in"],
                             capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_nettop_full(out)


def snapshot(include_nettop: bool = True) -> List[Row]:
    """All inet sockets: connections and listeners, with their owning process."""
    if psutil is None:
        return []
    try:
        conns = [(c, c.pid) for c in psutil.net_connections(kind="inet")]
    except psutil.AccessDenied:
        # Not root: only this user's processes are visible.
        conns = []
        for proc in psutil.process_iter():
            try:
                conns.extend((c, proc.pid) for c in proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
    cache: Dict[int, Dict[str, Any]] = {}
    rows: List[Row] = []
    seen = set()
    for c, pid in conns:
        if not c.laddr:
            continue
        proto = "tcp" if c.type == _SOCK_STREAM else "udp"
        row: Row = {
            "proto": proto,
            "local_ip": c.laddr.ip, "local_port": c.laddr.port,
            "remote_ip": c.raddr.ip if c.raddr else None,
            "remote_port": c.raddr.port if c.raddr else None,
            "state": c.status if c.status and c.status != "NONE" else None,
            "source": "socket",
        }
        row.update(_proc_details(pid, cache))
        seen.add((proto, c.laddr.port))
        rows.append(row)
    if include_nettop:
        for row in _nettop_rows():
            if (row["proto"], row["local_port"]) in seen or not row["remote_ip"]:
                continue
            details = _proc_details(row["pid"], cache)
            row.update({k: v for k, v in details.items() if v})
            row.setdefault("app", app_name_from_exe(row.get("exe"), row.get("process") or "?"))
            row["state"] = "ESTABLISHED" if row["proto"] == "tcp" else None
            rows.append(row)
    for row in rows:
        row["listening"] = is_listener(row)
    return rows


# macOS hands out client ports from this range; a UDP socket bound here with
# no peer is an app's outgoing socket (QUIC, DNS, media), not a service.
EPHEMERAL_START = 49152


def is_listener(row: Row) -> bool:
    if row.get("state") == "LISTEN":
        return True
    # Bound UDP sockets on a fixed port are services too (mDNS, AirPlay, dev servers).
    port = row.get("local_port") or 0
    return (row.get("proto") == "udp" and not row.get("remote_ip") and row.get("source") == "socket"
            and 0 < port < EPHEMERAL_START)


def exposure(local_ip: Optional[str]) -> str:
    """Who can reach a listening socket bound to *local_ip*."""
    if not local_ip:
        return "unknown"
    if local_ip.startswith("127.") or local_ip == "::1":
        return "this_mac"
    if local_ip in ("0.0.0.0", "::", "*"):
        return "all_networks"
    if local_ip.startswith("fe80:"):
        return "link_local"
    return "lan"


EXPOSURE_LABELS = {
    "this_mac": "This Mac only",
    "all_networks": "Any network you join",
    "lan": "Local network",
    "link_local": "Local link (IPv6)",
    "unknown": "Unknown",
}
