"""
"Who's on my network?" — local device inventory, plus optional nmap scans.

Discovery is passive: the kernel's ARP / neighbour table already lists
every device this Mac has exchanged packets with on the local network, and
the hostname cache knows the names devices announce over mDNS / DNS.  A new
MAC address appearing after the first inventory raises a low-severity
"new device" alert.

Active scanning (``nmap -sV``) is opt-in, on demand, and restricted to
private / link-local addresses and this Mac's own addresses: it identifies
what a device on *your* network is (printer, NAS, camera, TV) and which
services it exposes.  Scanning internet hosts is refused on purpose — it
warns the operator, can be illegal, and InternetDB already provides that
data passively.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..alerts.model import Alert, AlertType, Severity

logger = logging.getLogger(__name__)

_ARP_LINE = re.compile(
    r"^\S+ \((?P<ip>[0-9.]+)\) at (?P<mac>[0-9a-f:]+) on (?P<iface>\S+)(?P<rest>.*)$", re.I)

# A few vendors worth naming; the full IEEE registry is ~5 MB.
_OUI = {
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue", "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "00:11:32": "Synology", "90:09:d0": "Synology", "24:5e:be": "QNAP", "00:08:9b": "QNAP",
    "18:b4:30": "Nest", "64:16:66": "Nest", "f4:f5:d8": "Google", "54:60:09": "Google",
    "44:65:0d": "Amazon", "fc:65:de": "Amazon", "68:54:fd": "Amazon", "74:c2:46": "Amazon",
    "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link", "98:da:c4": "TP-Link",
    "a0:63:91": "Netgear", "c4:04:15": "Netgear",
    "f0:9f:c2": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "3c:5a:b4": "Google", "00:04:20": "Logitech", "5c:aa:fd": "Sonos", "00:0e:58": "Sonos",
    "b8:e9:37": "Sonos", "00:1e:c2": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "00:00:48": "Epson", "64:eb:8c": "Epson",
    "3c:2a:f4": "Brother", "00:80:77": "Brother", "a0:d3:c1": "HP", "3c:d9:2b": "HP",
    "00:1b:a9": "Brother", "b4:79:a7": "Samsung", "8c:79:f5": "Samsung", "d0:03:4b": "Apple",
    "2c:aa:8e": "Wyze", "7c:78:b2": "Wyze", "ac:84:c6": "TP-Link Kasa",
    "d8:eb:46": "Google", "a4:77:33": "Google", "00:24:e4": "Withings",
}


def parse_arp(output: str) -> List[Dict[str, Any]]:
    """``arp -an`` → [{ip, mac, iface}] (incomplete / broadcast entries dropped)."""
    out = []
    for line in output.splitlines():
        m = _ARP_LINE.match(line.strip())
        if not m:
            continue
        mac = ":".join(p.zfill(2) for p in m.group("mac").lower().split(":"))
        if mac in ("ff:ff:ff:ff:ff:ff",) or mac.startswith("01:00:5e"):
            continue
        ip = m.group("ip")
        if ip.endswith(".255") or ip.startswith(("224.", "239.", "169.254.255")):
            continue
        out.append({"ip": ip, "mac": mac, "iface": m.group("iface"),
                    "permanent": "permanent" in m.group("rest")})
    return out


def vendor(mac: str) -> Optional[str]:
    return _OUI.get(mac[:8])


def is_randomized(mac: str) -> bool:
    """Locally administered MAC — iPhones / Android / Windows "private Wi-Fi address"."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def _arp_table() -> str:
    try:
        return subprocess.run(["/usr/sbin/arp", "-an"], capture_output=True, text=True,
                              timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def nmap_path() -> Optional[str]:
    for candidate in ("/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"):
        if os.path.exists(candidate):
            return candidate
    return shutil.which("nmap")


def scan_allowed(ip: str, own_ips: frozenset) -> bool:
    """Only private, link-local, and this Mac's own addresses may be scanned."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if ip in own_ips:
        return True
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return addr.is_loopback
    return addr.is_private or addr.is_link_local


def parse_nmap_xml(text: str) -> Dict[str, Any]:
    root = ET.fromstring(text)
    host = root.find("host")
    result: Dict[str, Any] = {"ports": [], "up": False}
    if host is None:
        return result
    status = host.find("status")
    result["up"] = status is not None and status.get("state") == "up"
    for hn in host.findall("hostnames/hostname"):
        result.setdefault("hostnames", []).append(hn.get("name"))
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") not in ("open", "open|filtered"):
            continue
        svc = port.find("service")
        result["ports"].append({
            "port": int(port.get("portid")),
            "proto": port.get("protocol"),
            "state": state.get("state"),
            "service": svc.get("name") if svc is not None else None,
            "product": " ".join(x for x in (
                svc.get("product") if svc is not None else None,
                svc.get("version") if svc is not None else None) if x) or None,
        })
    match = host.find("os/osmatch")
    if match is not None:
        result["os"] = match.get("name")
    return result


_RUNNING: set = set()  # live nmap processes, so shutdown can stop them


def kill_scans() -> None:
    """Terminate any nmap scan still running (daemon shutdown)."""
    for proc in list(_RUNNING):
        try:
            proc.kill()
        except OSError:
            pass


def run_nmap(ip: str, top_ports: int = 200, timeout: float = 180.0,
             runner: Optional[Callable[[List[str], float], str]] = None) -> Dict[str, Any]:
    binary = nmap_path()
    if runner is None and not binary:
        raise RuntimeError("nmap is not installed. Install it with: brew install nmap")
    args = [binary or "nmap", "-sV", "--version-light", "-T4", "-Pn", "--top-ports", str(top_ports),
            "-oX", "-", ip]
    if runner is None:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _RUNNING.add(proc)
        try:
            text, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise RuntimeError(f"nmap took longer than {timeout:.0f}s and was stopped") from None
        finally:
            _RUNNING.discard(proc)
        if proc.returncode != 0 and not text:
            raise RuntimeError(((err or "nmap failed").strip().splitlines() or ["nmap failed"])[-1])
    else:
        text = runner(args, timeout)
    return parse_nmap_xml(text)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

class LanInventory:
    """
    Persistent inventory of devices seen on the local network.

    Args:
        db_path:   SQLite file (the events DB).
        emit:      Called with an :class:`Alert` for each new device.
        hostname:  ``ip -> name`` (the daemon's passive hostname cache).
        arp:       Injectable ``() -> arp -an output`` (tests).
        learning_seconds: New-device alerts start this long after the
                   inventory was first created, so the initial sweep of an
                   existing network stays quiet.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        emit: Optional[Callable[[Alert], None]] = None,
        hostname: Optional[Callable[[str], Optional[str]]] = None,
        arp: Optional[Callable[[], str]] = None,
        learning_seconds: float = 3600.0,
        own_ips: Optional[Callable[[], frozenset]] = None,
    ) -> None:
        self.db_path = Path(db_path) if db_path else None
        self.emit = emit
        self.hostname = hostname or (lambda ip: None)
        self.arp = arp or _arp_table
        self.learning_seconds = learning_seconds
        self.own_ips = own_ips or (lambda: frozenset())
        self._lock = threading.Lock()
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._created = time.time()
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._load()

    # --- persistence ----------------------------------------------------------

    def _conn(self) -> Optional[sqlite3.Connection]:
        if not self.db_path:
            return None
        try:
            conn = sqlite3.connect(str(self.db_path), timeout=5)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS lan_devices (mac TEXT PRIMARY KEY, ip TEXT, name TEXT,"
                " iface TEXT, first_seen REAL, last_seen REAL, scan TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            return conn
        except sqlite3.Error as exc:
            logger.debug("lan inventory db unavailable: %s", exc)
            return None

    def _load(self) -> None:
        conn = self._conn()
        if conn is None:
            return
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'lan_created'").fetchone()
            if row:
                self._created = float(row[0])
            else:
                conn.execute("INSERT INTO meta VALUES ('lan_created', ?)", (str(self._created),))
                conn.commit()
            for mac, ip, name, iface, first, last, scan in conn.execute("SELECT * FROM lan_devices"):
                self._devices[mac] = {"mac": mac, "ip": ip, "name": name, "iface": iface,
                                      "first_seen": first, "last_seen": last}
                if scan:
                    self._scans[mac] = json.loads(scan)
        finally:
            conn.close()

    def _save(self, dev: Dict[str, Any]) -> None:
        conn = self._conn()
        if conn is None:
            return
        try:
            scan = self._scans.get(dev["mac"])
            conn.execute("INSERT OR REPLACE INTO lan_devices VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (dev["mac"], dev["ip"], dev.get("name"), dev.get("iface"),
                          dev["first_seen"], dev["last_seen"], json.dumps(scan) if scan else None))
            conn.commit()
        finally:
            conn.close()

    # --- refresh ----------------------------------------------------------------

    def refresh(self) -> List[Dict[str, Any]]:
        """Read the neighbour table; returns newly discovered devices."""
        now = time.time()
        new = []
        own = self.own_ips()
        for entry in parse_arp(self.arp()):
            if entry["ip"] in own:
                continue
            with self._lock:
                dev = self._devices.get(entry["mac"])
                is_new = dev is None
                if is_new:
                    dev = {"mac": entry["mac"], "first_seen": now}
                    self._devices[entry["mac"]] = dev
                dev.update({"ip": entry["ip"], "iface": entry["iface"], "last_seen": now})
                name = self.hostname(entry["ip"])
                if name:
                    dev["name"] = name
            self._save(dev)
            if is_new:
                new.append(dev)
        if new and self.emit and now - self._created >= self.learning_seconds:
            for dev in new:
                self.emit(self._new_device_alert(dev))
        return new

    def _new_device_alert(self, dev: Dict[str, Any]) -> Alert:
        label = dev.get("name") or vendor(dev["mac"]) or "an unidentified device"
        return Alert(
            alert_type=AlertType.ANOMALY,
            severity=Severity.LOW,
            message=f"New device on your network: {label} ({dev['ip']}, {dev['mac']})",
            src_ip=dev["ip"],
            rule_id="LAN-NEW-DEVICE",
            tags=["lan", "new_device"],
            confidence=0.9,
            evidence={"mac": dev["mac"], "ip": dev["ip"], "interface": dev.get("iface"),
                      "vendor": vendor(dev["mac"]), "randomized_mac": is_randomized(dev["mac"]),
                      "name": dev.get("name")},
            context={"direction": "local", "remote_ip": dev["ip"]},
        )

    def devices(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = [dict(d) for d in self._devices.values()]
        for d in rows:
            d["vendor"] = vendor(d["mac"])
            d["randomized_mac"] = is_randomized(d["mac"])
            d["online"] = now - (d.get("last_seen") or 0) < 600
            d["new"] = now - d["first_seen"] < 86400 and d["first_seen"] - self._created >= self.learning_seconds
            scan = self._scans.get(d["mac"])
            if scan:
                d["scan"] = scan
        rows.sort(key=lambda d: (not d["online"], d.get("ip") or ""))
        return rows

    # --- active scans --------------------------------------------------------------

    def scan(self, ip: str, runner=None) -> Dict[str, Any]:
        if not scan_allowed(ip, self.own_ips()):
            raise PermissionError("Only devices on your local network (or this Mac) can be scanned.")
        started = time.time()
        result = run_nmap(ip, runner=runner)
        result.update({"ip": ip, "scanned": started, "duration": round(time.time() - started, 1)})
        with self._lock:
            mac = next((m for m, d in self._devices.items() if d.get("ip") == ip), None)
            key = mac or f"ip:{ip}"
            self._scans[key] = result
            dev = self._devices.get(mac) if mac else None
        if dev:
            self._save(dev)
        return result

    def last_scan(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for key, scan in self._scans.items():
                if scan.get("ip") == ip:
                    return scan
        return None
