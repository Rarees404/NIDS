"""
"Mark as expected": user-managed rules that silence alerts you have
already reviewed (this app talking to that host is fine; stop telling me).

A rule matches when every field it sets matches the alert:

* ``kind``    — the UI kind (``tracker``, ``beacon``, ``attack`` …)
* ``rule_id`` — an exact detector rule
* ``app``     — the owning app (``context.app``)
* ``host``    — remote hostname; ``example.com`` also covers subdomains
* ``ip``      — remote IP

Rules are stored as JSON in the data directory so they survive restarts.
Allowlisted alerts are dropped before they reach the dashboard, database,
notifications, or auto-blocking.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .classify import classify
from .model import Alert

logger = logging.getLogger(__name__)

FIELDS = ("kind", "rule_id", "app", "host", "ip")


def _host_matches(rule_host: str, host: Optional[str]) -> bool:
    if not host:
        return False
    rule_host, host = rule_host.lower().rstrip("."), host.lower().rstrip(".")
    return host == rule_host or host.endswith("." + rule_host)


class Allowlist:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self._rules: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.hits = 0
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._rules = [r for r in data if isinstance(r, dict)]
        except (OSError, ValueError) as exc:
            logger.warning("Could not read allowlist %s: %s", self.path, exc)

    def _save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._rules, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            logger.error("Could not save allowlist: %s", exc)

    def rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._rules]

    def add(self, note: str = "", **fields: Any) -> Dict[str, Any]:
        rule = {k: str(v).strip() for k, v in fields.items() if k in FIELDS and v not in (None, "")}
        if not rule:
            raise ValueError("an allowlist rule needs at least one of: " + ", ".join(FIELDS))
        if set(rule) == {"kind"} and rule["kind"] in ("threat", "attack"):
            raise ValueError("silencing every threat or attack alert is too broad; add an app, host, or IP")
        rule.update({"id": uuid.uuid4().hex[:12], "created": time.time(), "note": note[:200], "hits": 0})
        with self._lock:
            self._rules.append(rule)
            self._save()
        return rule

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.get("id") != rule_id]
            changed = len(self._rules) != before
            if changed:
                self._save()
        return changed

    def match(self, alert: Any) -> Optional[Dict[str, Any]]:
        d = alert.to_dict() if isinstance(alert, Alert) else alert
        ctx = d.get("context") or {}
        ev = d.get("evidence") or {}
        kind = d.get("kind") or classify(d)
        host = ctx.get("remote_host") or ev.get("host") or ev.get("sni") or ev.get("query_name")
        ip = ctx.get("remote_ip") or d.get("dst_ip")
        with self._lock:
            for rule in self._rules:
                if "kind" in rule and rule["kind"] != kind:
                    continue
                if "rule_id" in rule and rule["rule_id"].upper() != (d.get("rule_id") or "").upper():
                    continue
                if "app" in rule and rule["app"] != ctx.get("app"):
                    continue
                if "host" in rule and not _host_matches(rule["host"], host):
                    continue
                if "ip" in rule and rule["ip"] not in (ip, d.get("src_ip"), d.get("dst_ip")):
                    continue
                return rule
        return None

    def __call__(self, alert: Alert) -> bool:
        """AlertManager filter: True drops the alert."""
        rule = self.match(alert)
        if rule is None:
            return False
        with self._lock:
            rule["hits"] = rule.get("hits", 0) + 1
            rule["last_hit"] = time.time()
        self.hits += 1
        return True
