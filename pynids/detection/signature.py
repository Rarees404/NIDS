"""
Signature-based detection engine for PyNIDS.

Rules are loaded from YAML and evaluated against each packet's network
metadata and dissected layer-7 fields.  The rule language supports:

- Simple equality shorthand: ``field: value``
- Operator-based conditions: ``{field: X, op: OP, value: Y}``
- Boolean combinators: ``all`` (AND), ``any`` (OR), ``not``
- Per-rule thresholds: alert only after N hits in T seconds per source

Supported operators
-------------------
``eq``          Exact equality (default)
``ne``          Not equal
``lt / gt``     Numeric less/greater-than (exclusive)
``lte / gte``   Numeric less/greater-than-or-equal
``in``          Value is in a list
``not_in``      Value is not in a list
``contains``    Substring / bytes subsequence
``startswith``  String prefix match
``regex``       Regular-expression match (re.search, case-insensitive)
``exists``      Field is present and not None (value ignored)

Field addressing
----------------
Plain names (``src_ip``, ``dst_port``, ``protocol``, ``payload_bytes``) map
to the packet *meta* dict.  Dot-notation addresses nested layer-7 fields::

    layer7.http.user_agent
    layer7.dns.query_name
    layer7.tls.sni
    layer7.tls.ja3

Rule YAML format
----------------
.. code-block:: yaml

    rules:
      - id: "SIG-001"
        description: "SSH brute-force probe"
        severity: HIGH
        confidence: 0.9
        mitre: "T1110"
        tags: [brute_force, credential_access]
        match:
          all:
            - {field: protocol, op: eq, value: tcp}
            - {field: dst_port, op: eq, value: 22}
        threshold:
          count: 5
          seconds: 30
        action: alert
"""
from __future__ import annotations

import logging
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import yaml

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_rules(path: str) -> List[Dict[str, Any]]:
    """Load and return a list of rule dicts from *path*."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", [])


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _get_field(field: str, meta: dict, layer7: dict) -> Any:
    """Resolve a (possibly dotted) field name against meta + layer7."""
    parts = field.split(".")
    if parts[0] == "layer7":
        obj: Any = layer7
        for part in parts[1:]:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj
    return meta.get(field)


def _apply_op(op: str, actual: Any, expected: Any) -> bool:
    """Apply *op* between *actual* (from packet) and *expected* (from rule)."""
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "exists":
        return actual is not None
    if actual is None:
        return False
    if op == "lt":
        return actual < expected
    if op == "gt":
        return actual > expected
    if op == "lte":
        return actual <= expected
    if op == "gte":
        return actual >= expected
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op == "contains":
        if isinstance(actual, bytes) and isinstance(expected, str):
            return expected.encode() in actual
        if isinstance(actual, bytes) and isinstance(expected, bytes):
            return expected in actual
        return str(expected) in str(actual)
    if op == "startswith":
        return str(actual).startswith(str(expected))
    if op == "regex":
        return bool(re.search(str(expected), str(actual), re.IGNORECASE))
    logger.warning("Unknown rule op: %r", op)
    return False


def _eval_node(node: Any, meta: dict, layer7: dict) -> bool:
    """
    Recursively evaluate a rule condition node.

    Nodes can be:
    - ``{all: [...]}``  — all sub-nodes must match (AND)
    - ``{any: [...]}``  — at least one sub-node must match (OR)
    - ``{not: node}``   — negate sub-node
    - ``{field, op, value}`` — leaf condition
    - ``{field: value, ...}`` — shorthand equality (multiple keys = AND)
    """
    if not isinstance(node, dict):
        return False

    if "all" in node:
        return all(_eval_node(child, meta, layer7) for child in node["all"])
    if "any" in node:
        return any(_eval_node(child, meta, layer7) for child in node["any"])
    if "not" in node:
        return not _eval_node(node["not"], meta, layer7)

    if "field" in node:
        # Structured form: {field: X, op: OP, value: V}
        actual = _get_field(node["field"], meta, layer7)
        op = node.get("op", "eq")
        value = node.get("value")
        return _apply_op(op, actual, value)

    # Shorthand: {key: value, key2: value2, …}  — all must match
    return all(
        _apply_op("eq", _get_field(k, meta, layer7), v)
        for k, v in node.items()
    )


# ---------------------------------------------------------------------------
# Signature detector
# ---------------------------------------------------------------------------

class SignatureDetector(BaseDetector):
    """
    Match packets against a YAML rule set.

    Each rule is evaluated against every packet.  If ``threshold`` is set
    the alert is only emitted once the rule has matched *count* times within
    *seconds* for the same source IP.

    Args:
        rules: List of rule dictionaries (as returned by :func:`load_rules`).
    """

    def __init__(self, rules: List[Dict[str, Any]]) -> None:
        self._rules = rules
        # threshold tracking: {(rule_id, src_ip): deque of timestamps}
        self._threshold_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        # per-rule hit counter for statistics
        self._hit_counts: Dict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "signature"

    def update_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Hot-reload rules without restarting the detector."""
        self._rules = rules
        self._threshold_hits.clear()
        logger.info("SignatureDetector: reloaded %d rules", len(rules))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        src_ip = meta.get("src_ip") or ""
        for rule in self._rules:
            try:
                yield from self._eval_rule(rule, meta, layer7, src_ip)
            except Exception as exc:
                logger.error("Rule %r raised: %s", rule.get("id"), exc)

    def _eval_rule(
        self,
        rule: Dict[str, Any],
        meta: dict,
        layer7: dict,
        src_ip: str,
    ) -> Iterable[Alert]:
        match_node = rule.get("match")
        if match_node is None:
            return

        if not _eval_node(match_node, meta, layer7):
            return

        rule_id = rule.get("id", "unknown")

        # Threshold gate
        if "threshold" in rule:
            thresh = rule["threshold"]
            count = int(thresh.get("count", 1))
            window = float(thresh.get("seconds", 60))
            key = (rule_id, src_ip)
            bucket = self._threshold_hits[key]
            now = time.time()
            # Expire old entries
            while bucket and (now - bucket[0]) > window:
                bucket.popleft()
            bucket.append(now)
            if len(bucket) < count:
                return  # Haven't hit threshold yet

        self._hit_counts[rule_id] += 1

        severity = Severity(rule.get("severity", "MEDIUM").upper())
        yield Alert(
            alert_type=AlertType.SIGNATURE,
            severity=severity,
            message=rule.get("description", f"Signature match: {rule_id}"),
            src_ip=src_ip or None,
            dst_ip=meta.get("dst_ip"),
            src_port=meta.get("src_port"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            rule_id=rule_id,
            confidence=float(rule.get("confidence", 1.0)),
            tags=list(rule.get("tags", [])),
            mitre_technique=rule.get("mitre"),
            evidence={
                "payload_preview": (meta.get("payload_bytes") or b"")[:128],
                "layer7": {k: v for k, v in layer7.items() if k != "headers"},
            },
        )

    # Legacy compatibility (used by the existing test)
    def evaluate_packet(self, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Legacy API: return a list of alert dicts.

        .. deprecated::
            Use :meth:`analyze` instead which returns typed :class:`Alert` objects.
        """
        alerts = []
        for rule in self._rules:
            when = rule.get("when") or rule.get("match") or {}
            if self._legacy_matches(when, meta):
                alerts.append(
                    {
                        "type": "signature",
                        "rule_id": rule.get("id", "unknown"),
                        "message": rule.get("description", "signature match"),
                        "meta": meta,
                    }
                )
        return alerts

    @staticmethod
    def _legacy_matches(when: Dict[str, Any], meta: Dict[str, Any]) -> bool:
        for key, expected in when.items():
            if key == "payload_contains":
                payload = meta.get("payload_bytes", b"")
                needle = expected.encode() if isinstance(expected, str) else bytes(expected)
                if needle not in payload:
                    return False
            else:
                if meta.get(key) != expected:
                    return False
        return True
