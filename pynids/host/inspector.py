"""
One place that answers "what is this Mac doing right now, and should I
worry?" for the API, the CLI, and Claude's investigation tools.

It joins the live socket table with everything else PyNIDS knows: code
signatures, launchd persistence, hostnames learned from traffic, GeoIP,
threat-intel feeds, recent alerts, and cached IP lookups.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import codesign, connections
from .dossier import IpLookup, is_public
from .lan import LanInventory
from .persistence import PersistenceIndex

logger = logging.getLogger(__name__)

VIRUSTOTAL_FILE = "https://www.virustotal.com/gui/file/{sha}"
VIRUSTOTAL_IP = "https://www.virustotal.com/gui/ip-address/{ip}"

_FLAG_LABELS = {
    "unsigned": "Unsigned",
    "adhoc": "Ad-hoc signed",
    "invalid_signature": "Broken signature",
    "odd_path": "Unusual location",
    "intel": "On a blocklist",
    "beacon": "Regular check-ins",
    "c2": "Likely C2",
    "c2_infra": "Tagged C2 by Shodan",
    "exposed": "Reachable from the network",
    "persistent": "Starts automatically",
}


_EXPOSURE_RANK = {"unknown": 0, "this_mac": 1, "link_local": 2, "lan": 3, "all_networks": 4}
# Multicast discovery listeners every Mac runs (mDNS / Bonjour, SSDP, LLMNR).
_DISCOVERY_PORTS = frozenset({5353, 1900, 5355})


def _bundle(exe: Optional[str]) -> Optional[str]:
    """``/Applications/X.app/Contents/…/Y.app/…`` → ``/Applications/X.app``."""
    if exe and ".app/" in exe:
        return exe[:exe.find(".app/") + 4]
    return None


def _scope(ip: Optional[str]) -> str:
    if not ip:
        return "none"
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_global:
        return "internet"
    return "lan"


class HostInspector:
    def __init__(
        self,
        live: Any = None,
        signatures: Optional[codesign.SignatureChecker] = None,
        persistence: Optional[PersistenceIndex] = None,
        lookups: Optional[IpLookup] = None,
        lan: Optional[LanInventory] = None,
        hostnames: Any = None,
        geo: Any = None,
        intel: Optional[Callable[[], Any]] = None,
        baseline: Any = None,
        db_path: Optional[Path] = None,
        snapshot: Callable[[], List[Dict[str, Any]]] = connections.snapshot,
    ) -> None:
        self.live = live
        self.signatures = signatures or codesign.SignatureChecker()
        self.persistence = persistence or PersistenceIndex()
        self.lookups = lookups
        self.lan = lan
        self.hostnames = hostnames
        self.geo = geo
        self._intel = intel or (lambda: None)
        self.baseline = baseline
        self.db_path = Path(db_path) if db_path else None
        self._snapshot = snapshot
        self._conn_cache: Dict[bool, Any] = {}
        self._build_lock = threading.Lock()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _intel_hit(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        intel = self._intel()
        if not intel or not ip or not is_public(ip):
            return None
        entry = intel.check_ip(ip)
        return entry.__dict__ if entry else None

    def _alert_index(self) -> Dict[str, Dict[str, Any]]:
        """remote ip → {beacon, c2, count, worst} from the live alert buffer."""
        out: Dict[str, Dict[str, Any]] = {}
        if not self.live:
            return out
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for a in self.live.recent_alerts(limit=500):
            ctx = a.get("context") or {}
            ip = ctx.get("remote_ip") or a.get("dst_ip")
            if not ip:
                continue
            rec = out.setdefault(ip, {"count": 0, "worst": None, "beacon": False, "c2": False})
            rec["count"] += 1
            if order.get(a.get("severity"), 0) > order.get(rec["worst"] or "", 0):
                rec["worst"] = a.get("severity")
            tags = set(a.get("tags") or ())
            rec["beacon"] |= "beaconing" in tags
            rec["c2"] |= "likely_c2" in tags
        return out

    def _infra_tags(self, ip: Optional[str]) -> List[str]:
        if not self.lookups or not ip:
            return []
        hit = self.lookups.cached(ip)
        return ((hit or {}).get("internetdb") or {}).get("tags") or []

    def signature(self, exe: Optional[str], block: bool = False) -> Optional[Dict[str, Any]]:
        if not exe:
            return None
        if codesign.is_system_path(exe):  # the sealed system volume: Apple-signed by construction
            return {"status": codesign.APPLE, "label": codesign.LABELS[codesign.APPLE], "system": True}
        return self.signatures.check(exe) if block else self.signatures.lookup(exe)

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------

    def connections(self, include_local: bool = False, max_age: float = 3.0) -> Dict[str, Any]:
        """
        Joined socket table, cached for *max_age* seconds.

        The dashboard, the attention summary and Claude's tools all poll this;
        only one caller rebuilds at a time, and concurrent callers get the
        previous snapshot instead of starting their own.
        """
        hit = self._conn_cache.get(include_local)
        if hit and time.time() - hit["generated"] < max_age:
            return hit
        if not self._build_lock.acquire(blocking=hit is None):
            return hit  # someone else is rebuilding; slightly stale is fine
        try:
            hit = self._conn_cache.get(include_local)
            if hit and time.time() - hit["generated"] < max_age:
                return hit  # built while we waited
            started = time.time()
            result = self._build_connections(include_local)
            took = time.time() - started
            if took > 2.0:
                logger.warning("Building the connection table took %.1fs", took)
            self._conn_cache[include_local] = result
            return result
        finally:
            self._build_lock.release()

    def _build_connections(self, include_local: bool) -> Dict[str, Any]:
        rows = self._snapshot()
        remotes = self.live.remote_index() if self.live else {}
        alerts = self._alert_index()
        conns: List[Dict[str, Any]] = []
        listeners: List[Dict[str, Any]] = []
        listen_index: Dict[Any, Dict[str, Any]] = {}
        programs: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            exe = row.get("exe") or ""
            sig = self.signature(exe) if exe else None
            verdict = codesign.assess(exe, sig) if exe else {"flags": [], "risk": 0, "reasons": []}
            flags = list(verdict["flags"])
            risk = verdict["risk"]
            if row["listening"]:
                exp = connections.exposure(row.get("local_ip"))
                key = (row.get("pid") or exe, row["proto"], row.get("local_port"))
                prev = listen_index.get(key)
                if prev is not None:
                    # Same service on several addresses (0.0.0.0 + ::, or per-interface mDNS).
                    if row.get("local_ip") not in prev["addresses"]:
                        prev["addresses"].append(row.get("local_ip"))
                    if _EXPOSURE_RANK[exp] > _EXPOSURE_RANK[prev["exposure"]]:
                        prev.update(exposure=exp, exposure_label=connections.EXPOSURE_LABELS[exp])
                else:
                    item = {**row, "exposure": exp, "exposure_label": connections.EXPOSURE_LABELS[exp],
                            "addresses": [row.get("local_ip")],
                            "signature": (sig or {}).get("status"), "flags": flags, "risk": risk}
                    listen_index[key] = item
                    listeners.append(item)
            else:
                rip = row.get("remote_ip")
                if not rip:  # unconnected client socket: nothing to show
                    continue
                scope = _scope(rip)
                if scope == "loopback" and not include_local:
                    continue
                info = dict(remotes.get(rip) or {})
                if not info.get("remote_host") and self.hostnames is not None:
                    info["remote_host"] = self.hostnames.lookup(rip)
                if not info.get("country") and self.geo is not None and scope == "internet":
                    info.update(self.geo.lookup(rip) or {})
                hit = self._intel_hit(rip)
                al = alerts.get(rip or "", {})
                if hit:
                    flags.append("intel")
                    risk = 3
                if al.get("beacon"):
                    flags.append("beacon")
                    risk = max(risk, 2 if verdict["risk"] or not info.get("remote_host") else 1)
                if al.get("c2"):
                    flags.append("c2")
                    risk = 3
                if {"c2", "malware", "botnet"} & {t.lower() for t in self._infra_tags(rip)}:
                    flags.append("c2_infra")
                    risk = 3
                conns.append({
                    **row, "scope": scope,
                    "remote_host": info.get("remote_host"),
                    "country": info.get("country"), "country_name": info.get("country_name"),
                    "city": info.get("city"), "org": info.get("org"), "asn": info.get("asn"),
                    "bytes": info.get("bytes"), "alerts": al.get("count", 0),
                    "worst_alert": al.get("worst"),
                    "intel": hit, "signature": (sig or {}).get("status"),
                    "flags": flags, "risk": risk,
                })
            # Helpers inside one app bundle (Chrome's renderer, GPU, network
            # helpers …) are one program to the user.
            bundle = _bundle(exe)
            key = bundle or exe or f"pid:{row.get('pid')}"
            prog = programs.setdefault(key, {
                "exe": exe or None, "bundle": bundle, "binaries": set(),
                "app": row.get("app") or row.get("process") or "Unknown",
                "process": row.get("process"), "pids": set(), "user": row.get("user"),
                "signature": (sig or {}).get("status"), "signature_label": (sig or {}).get("label"),
                "authority": (sig or {}).get("authority"),
                "flags": set(), "risk": 0, "connections": 0, "listening": 0,
                "remotes": set(), "reasons": verdict["reasons"],
            })
            if row.get("pid"):
                prog["pids"].add(row["pid"])
            if exe:
                prog["binaries"].add(exe)
            row_risk = risk if row["listening"] else conns[-1]["risk"]
            if exe and row_risk > prog["risk"]:
                # Show the riskiest binary of the bundle.
                prog.update(exe=exe, signature=(sig or {}).get("status"), signature_label=(sig or {}).get("label"),
                            authority=(sig or {}).get("authority"), reasons=verdict["reasons"])
            prog["flags"] |= set(flags if row["listening"] else conns[-1]["flags"])
            prog["risk"] = max(prog["risk"], risk if row["listening"] else conns[-1]["risk"])
            if row["listening"]:
                prog["listening"] += 1
            else:
                prog["connections"] += 1
                if row.get("remote_ip"):
                    prog["remotes"].add(row["remote_ip"])

        for item in listeners:
            if item["exposure"] in ("all_networks", "lan") and item.get("local_port") not in _DISCOVERY_PORTS:
                item["flags"] = item["flags"] + ["exposed"]
        prog_list = []
        for prog in programs.values():
            if prog["exe"] and prog["risk"] >= 2:
                jobs = self.persistence.for_program(prog["exe"])
                if jobs:
                    prog["flags"].add("persistent")
                    prog["launchd"] = [{"label": j["label"], "plist": j["plist"]} for j in jobs[:3]]
            prog["pids"] = sorted(prog["pids"])
            prog["binaries"] = len(prog["binaries"])
            prog["flags"] = sorted(prog["flags"])
            prog["remotes"] = len(prog["remotes"])
            prog_list.append(prog)
        prog_list.sort(key=lambda p: (-p["risk"], -p["connections"], p["app"].lower()))
        conns.sort(key=lambda c: (-c["risk"], c.get("app") or "", c.get("remote_ip") or ""))
        listeners.sort(key=lambda r: (r["exposure"] == "this_mac", -r["risk"], r.get("local_port") or 0))
        return {
            "generated": time.time(),
            "connections": conns,
            "listening": listeners,
            "programs": prog_list,
            "flag_labels": _FLAG_LABELS,
            "summary": {
                "connections": len(conns),
                "internet": sum(1 for c in conns if c["scope"] == "internet"),
                "programs": len(prog_list),
                "flagged_programs": sum(1 for p in prog_list if p["risk"] >= 2),
                "exposed_ports": sum(1 for r in listeners if "exposed" in r["flags"]),
                "pending_signatures": sum(1 for p in prog_list if p["exe"] and not p["signature"]),
            },
        }

    def listening(self) -> List[Dict[str, Any]]:
        return self.connections()["listening"]

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------

    def program(self, exe: str, with_hash: bool = True) -> Dict[str, Any]:
        sig = self.signature(exe, block=True) or {}
        verdict = codesign.assess(exe, sig)
        sha = codesign.sha256_file(exe) if with_hash else None
        jobs = self.persistence.for_program(exe)
        snap = [r for r in self._snapshot() if r.get("exe") == exe]
        app = next((r.get("app") for r in snap if r.get("app")), None)
        live_app = self.live.app(app) if self.live and app else None
        countries = self.baseline.values(app, "country") if self.baseline and app else []
        first_net = self.baseline.first_seen(exe, "program") if self.baseline else None
        return {
            "exe": exe,
            "app": app or exe.rsplit("/", 1)[-1],
            "signature": sig,
            "assessment": verdict,
            "sha256": sha,
            "virustotal": VIRUSTOTAL_FILE.format(sha=sha) if sha else None,
            "launchd": jobs,
            "pids": sorted({r["pid"] for r in snap if r.get("pid")}),
            "connections": [{k: r.get(k) for k in ("proto", "local_ip", "local_port", "remote_ip",
                                                   "remote_port", "state", "listening")} for r in snap],
            "traffic": live_app,
            "usual_countries": countries,
            "first_network_use": first_net,
        }

    # ------------------------------------------------------------------
    # IP dossier
    # ------------------------------------------------------------------

    def _ip_alerts(self, ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if self.db_path and self.db_path.exists():
            try:
                conn = sqlite3.connect(str(self.db_path), timeout=5)
                conn.row_factory = sqlite3.Row
                for r in conn.execute(
                        "SELECT alert_id, timestamp, severity, rule_id, message FROM alerts"
                        " WHERE src_ip = ? OR dst_ip = ? ORDER BY timestamp DESC LIMIT ?",
                        (ip, ip, limit)):
                    rows.append(dict(r))
                conn.close()
            except sqlite3.Error:
                rows = []
        if not rows and self.live:
            for a in self.live.recent_alerts(limit=500):
                ctx = a.get("context") or {}
                if ip in (a.get("src_ip"), a.get("dst_ip"), ctx.get("remote_ip")):
                    rows.append({k: a.get(k) for k in ("alert_id", "timestamp", "severity", "rule_id", "message")})
                    if len(rows) >= limit:
                        break
        return rows

    def dossier(self, ip: str, external: Optional[bool] = None, refresh: bool = False) -> Dict[str, Any]:
        """Everything known about *ip*.  ``external=None`` uses cached lookups only."""
        try:
            ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            raise ValueError(f"not an IP address: {ip}") from None
        local: Dict[str, Any] = {"scope": _scope(ip)}
        remote = self.live.remote(ip) if self.live else None
        if remote:
            local.update({k: remote.get(k) for k in ("remote_host", "bytes", "packets", "apps", "alerts",
                                                     "first_seen", "last_seen", "country", "country_name",
                                                     "city", "org", "asn")})
        if not local.get("remote_host") and self.hostnames is not None:
            local["remote_host"] = self.hostnames.lookup(ip)
        if not local.get("country") and self.geo is not None and is_public(ip):
            local.update(self.geo.lookup(ip) or {})
        local["intel"] = self._intel_hit(ip)
        local["recent_alerts"] = self._ip_alerts(ip)
        local["connected_now"] = [
            {k: r.get(k) for k in ("app", "pid", "exe", "proto", "remote_port", "state")}
            for r in self._snapshot() if r.get("remote_ip") == ip
        ]
        if self.lan:
            dev = next((d for d in self.lan.devices() if d.get("ip") == ip), None)
            if dev:
                local["lan_device"] = dev
        out: Dict[str, Any] = {"ip": ip, "local": local,
                               "virustotal": VIRUSTOTAL_IP.format(ip=ip) if is_public(ip) else None}
        if self.lookups is not None:
            if external:
                out["external"] = self.lookups.lookup(ip, refresh=refresh)
            else:
                cached = self.lookups.cached(ip)
                out["external"] = ({**cached, "cached": True} if cached else
                                   {"ip": ip, "external": False, "pending": is_public(ip),
                                    "reason": "not looked up yet" if is_public(ip)
                                    else "private or reserved address — not looked up"})
            out["lookup_mode"] = self.lookups.mode
        return out

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def launch_items(self, refresh: bool = False) -> List[Dict[str, Any]]:
        out = []
        for job in self.persistence.jobs(refresh=refresh):
            prog = job.get("program")
            sig = self.signature(prog) if prog else None
            verdict = codesign.assess(prog, sig) if prog else {"flags": [], "risk": 0, "reasons": []}
            missing = bool(prog) and not Path(prog).exists()
            out.append({**job, "signature": (sig or {}).get("status"),
                        "signature_label": (sig or {}).get("label"),
                        "authority": (sig or {}).get("authority"),
                        "flags": verdict["flags"] + (["missing_program"] if missing else []),
                        "risk": verdict["risk"], "reasons": verdict["reasons"]})
        out.sort(key=lambda j: (-j["risk"], -j["modified"]))
        return out


def dumps(obj: Any) -> str:
    """Compact JSON for tool results (sets → lists)."""
    return json.dumps(obj, default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o))
