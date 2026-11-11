"""
Signature-based detection engine for PyNIDS.

Rules are loaded from YAML, validated and compiled once, then evaluated
against each packet's network metadata, dissected layer-7 fields, flow
state and enrichment context.  The rule language supports:

- Simple equality shorthand: ``field: value``
- Operator-based conditions: ``{field: X, op: OP, value: Y}``
- Boolean combinators: ``all`` (AND), ``any`` (OR), ``not``
- Per-rule thresholds: alert only after N hits in T seconds, tracked per
  source, destination, pair, flow, or globally
- Message templates: ``message: "FTP login to {dst_ip}"``

Supported operators
-------------------
``eq``            Exact equality (default)
``ne``            Not equal
``lt / gt``       Numeric less/greater-than (exclusive)
``lte / gte``     Numeric less/greater-than-or-equal
``in``            Value is in a list
``not_in``        Value is not in a list
``contains``      Substring / bytes subsequence
``not_contains``  Negated ``contains`` (a missing field does not match)
``startswith``    Prefix match
``endswith``      Suffix match
``regex``         Regular-expression search, case-insensitive
``cidr``          IP address is inside a network (or any of a list)
``exists``        Field is present and not None (value ignored)

Text operators work on raw payload bytes too: the payload is read as
Latin-1 (one character per byte), and ``\\xNN`` escapes in a rule value
stand for raw bytes, so ``"\\x00\\x00\\x00\\x85\\xffSMB"`` matches binary data.

Field addressing
----------------
Plain names (``src_ip``, ``dst_port``, ``protocol``, ``payload_bytes``) map
to the packet *meta* dict.  Dot-notation addresses nested layer-7 fields::

    layer7.http.user_agent
    layer7.dns.query_name
    layer7.tls.sni
    layer7.tls.ja3

Computed fields
---------------
``payload_len``              Bytes of application payload in this packet
``tcp.syn``                  A connection attempt: SYN set, ACK clear
``tcp.synack / fin / rst``   Flag tests
``tcp.null / tcp.xmas``      No flags at all / FIN+PSH+URG (stealth scans)
``direction``                outbound | inbound | local | transit (needs enrichment)
``src_scope / dst_scope``    public | private | loopback | link_local | multicast
``context.<key>``            Enrichment: ``context.app``, ``context.remote_host``,
                             ``context.country``, ``context.signature`` …
``flow.new``                 First packet of its flow
``flow.packets / bytes / bytes_out / bytes_in / duration / state``

Rule YAML format
----------------
.. code-block:: yaml

    rules:
      - id: "SIG-001"
        description: "SSH connection attempts from the internet"
        severity: HIGH
        confidence: 0.9
        mitre: "T1110"
        tags: [brute_force, credential_access]
        match:
          all:
            - {field: tcp.syn, op: eq, value: true}
            - {field: dst_port, op: eq, value: 22}
            - {field: src_scope, op: eq, value: public}
        threshold:
          count: 5
          seconds: 30
          track_by: src_ip        # src_ip (default) | dst_ip | pair | flow | global
        message: "SSH connection attempts from {src_ip}"
        why: "What this means, shown in the alert drawer."
        response: "What to do about it."
        references: ["https://attack.mitre.org/techniques/T1110/"]
        enabled: true
        action: alert
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import defaultdict, deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

import yaml

from .base import BaseDetector
from ..alerts.model import Alert, AlertType, Severity
from ..flow.tracker import Flow
from ..protocols.stealth import classify_ip

logger = logging.getLogger(__name__)

OPS = frozenset({
    "eq", "ne", "lt", "gt", "lte", "gte", "in", "not_in", "contains", "not_contains",
    "startswith", "endswith", "regex", "cidr", "exists",
})
_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_TRACK_BY = ("src_ip", "dst_ip", "pair", "flow", "global")
_RULE_KEYS = frozenset({
    "id", "description", "severity", "confidence", "mitre", "tags", "match", "when",
    "threshold", "action", "message", "why", "response", "references", "enabled",
})

_FLAG_FIN, _FLAG_SYN, _FLAG_RST, _FLAG_PSH, _FLAG_ACK, _FLAG_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def load_rules(path: str) -> List[Dict[str, Any]]:
    """Load and return a list of rule dicts from *path*."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    rules = data.get("rules", []) if isinstance(data, dict) else []
    return rules if isinstance(rules, list) else []


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------

def _flow_field(name: str, flow: Optional[Flow], meta: dict) -> Any:
    if flow is None:
        return None
    if name == "new":
        return flow.packet_count <= 1
    if name == "packets":
        return flow.packet_count
    if name == "bytes":
        return flow.byte_count
    if name == "bytes_out":
        return flow.bytes_from_src
    if name == "bytes_in":
        return flow.byte_count - flow.bytes_from_src
    if name == "duration":
        return flow.duration
    if name == "state":
        return getattr(flow.state, "value", flow.state)
    if name == "initiator":
        return flow.src_ip
    return None


def _tcp_field(name: str, meta: dict) -> Any:
    if meta.get("protocol") != "tcp":
        return None
    flags = meta.get("tcp_flags") or 0
    if name == "syn":
        return bool(flags & _FLAG_SYN) and not flags & _FLAG_ACK
    if name == "synack":
        return bool(flags & _FLAG_SYN) and bool(flags & _FLAG_ACK)
    if name == "fin":
        return bool(flags & _FLAG_FIN)
    if name == "rst":
        return bool(flags & _FLAG_RST)
    if name == "ack":
        return bool(flags & _FLAG_ACK)
    if name == "null":
        return flags & 0x3F == 0
    if name == "xmas":
        return flags & (_FLAG_FIN | _FLAG_PSH | _FLAG_URG) == (_FLAG_FIN | _FLAG_PSH | _FLAG_URG)
    if name == "flags":
        return flags
    return None


def _get_field(field: str, meta: dict, layer7: dict, flow: Optional[Flow] = None) -> Any:
    """Resolve a (possibly dotted or computed) field name against the packet."""
    if "." not in field:
        if field in meta:
            return meta[field]
        if field == "payload_len":
            return len(meta.get("payload_bytes") or b"")
        if field == "direction":
            return (layer7.get("context") or {}).get("direction")
        if field == "src_scope":
            return classify_ip(meta.get("src_ip")) if meta.get("src_ip") else None
        if field == "dst_scope":
            return classify_ip(meta.get("dst_ip")) if meta.get("dst_ip") else None
        return None

    head, _, rest = field.partition(".")
    if head == "layer7":
        obj: Any = layer7
        for part in rest.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj
    if head == "tcp":
        return _tcp_field(rest, meta)
    if head == "flow":
        return _flow_field(rest, flow, meta)
    if head == "context":
        return (layer7.get("context") or {}).get(rest)
    return meta.get(field)


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _unescape(value: Any) -> str:
    """Rule text → the characters it should match (``\\xNN`` = one raw byte)."""
    return _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), str(value))


def _text(actual: Any) -> str:
    """Packet value → text.  Bytes map 1:1 to characters (Latin-1)."""
    if isinstance(actual, (bytes, bytearray)):
        return bytes(actual).decode("latin-1")
    return str(actual)


def _networks(value: Any) -> List[Any]:
    items = value if isinstance(value, (list, tuple, set)) else [value]
    return [ipaddress.ip_network(str(v).strip(), strict=False) for v in items]


def _in_networks(actual: Any, nets: List[Any]) -> bool:
    try:
        addr = ipaddress.ip_address(str(actual))
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in nets)


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
    try:
        if op == "lt":
            return actual < expected
        if op == "gt":
            return actual > expected
        if op == "lte":
            return actual <= expected
        if op == "gte":
            return actual >= expected
    except TypeError:
        return False
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op == "contains":
        if isinstance(actual, (list, tuple, set, frozenset)):
            return expected in actual
        if isinstance(expected, (bytes, bytearray)):
            expected = bytes(expected).decode("latin-1")
        return _unescape(expected) in _text(actual)
    if op == "not_contains":
        return not _apply_op("contains", actual, expected)
    if op == "startswith":
        return _text(actual).startswith(_unescape(expected))
    if op == "endswith":
        return _text(actual).endswith(_unescape(expected))
    if op == "regex":
        return bool(re.search(str(expected), _text(actual), re.IGNORECASE))
    if op == "cidr":
        try:
            return _in_networks(actual, _networks(expected))
        except ValueError:
            return False
    logger.warning("Unknown rule op: %r", op)
    return False


def _eval_node(node: Any, meta: dict, layer7: dict, flow: Optional[Flow] = None) -> bool:
    """
    Recursively evaluate a rule condition node (uncompiled form).

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
        return all(_eval_node(child, meta, layer7, flow) for child in node["all"])
    if "any" in node:
        return any(_eval_node(child, meta, layer7, flow) for child in node["any"])
    if "not" in node:
        return not _eval_node(node["not"], meta, layer7, flow)

    if "field" in node:
        actual = _get_field(node["field"], meta, layer7, flow)
        return _apply_op(node.get("op", "eq"), actual, node.get("value"))

    return all(
        _apply_op("eq", _get_field(k, meta, layer7, flow), v)
        for k, v in node.items()
    )


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

class RuleError(ValueError):
    """A rule that cannot be compiled (bad operator, regex, CIDR, shape)."""


class _Packet:
    """One packet under evaluation; decodes the payload to text at most once."""

    __slots__ = ("meta", "layer7", "flow", "_payload_text")

    def __init__(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> None:
        self.meta = meta
        self.layer7 = layer7
        self.flow = flow
        self._payload_text: Optional[str] = None

    def get(self, field: str) -> Any:
        return _get_field(field, self.meta, self.layer7, self.flow)

    def text(self, field: str) -> Optional[str]:
        if field == "payload_bytes":
            if self._payload_text is None:
                self._payload_text = _text(self.meta.get("payload_bytes") or b"")
            return self._payload_text
        value = self.get(field)
        return None if value is None else _text(value)


Predicate = Callable[[_Packet], bool]
# Operators that can only be true when the field carries data.
_POSITIVE_OPS = frozenset({"eq", "in", "contains", "startswith", "endswith", "regex", "exists",
                           "lt", "gt", "lte", "gte"})


def _needs_data(field: str) -> bool:
    """True for fields that are empty on a packet without payload."""
    return field == "payload_bytes" or (
        field.startswith("layer7.") and not field.startswith("layer7.context"))


def _compile_leaf(field: Any, op: Any, value: Any) -> Predicate:
    if not isinstance(field, str) or not field:
        raise RuleError(f"condition has no field name: {field!r}")
    if op not in OPS:
        raise RuleError(f"unknown operator {op!r} on field {field!r}")

    if op == "regex":
        try:
            pattern = re.compile(str(value), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"invalid regex on {field!r}: {exc}") from None

        def _regex(pkt: _Packet) -> bool:
            text = pkt.text(field)
            return text is not None and pattern.search(text) is not None
        return _regex

    if op in ("contains", "not_contains", "startswith", "endswith"):
        if value is None:
            raise RuleError(f"{op} on {field!r} needs a value")
        needle = _unescape(_text(value) if isinstance(value, (bytes, bytearray)) else value)
        negate = op == "not_contains"

        def _textual(pkt: _Packet) -> bool:
            raw = pkt.get(field) if field != "payload_bytes" else pkt.meta.get("payload_bytes")
            if raw is None:
                return False
            if op != "startswith" and op != "endswith" and isinstance(raw, (list, tuple, set, frozenset)):
                return (value in raw) != negate
            text = pkt.text(field) or ""
            if op == "startswith":
                return text.startswith(needle)
            if op == "endswith":
                return text.endswith(needle)
            return (needle in text) != negate
        return _textual

    if op == "cidr":
        try:
            nets = _networks(value)
        except ValueError as exc:
            raise RuleError(f"invalid CIDR on {field!r}: {exc}") from None
        return lambda pkt: (lambda a: a is not None and _in_networks(a, nets))(pkt.get(field))

    if op in ("in", "not_in"):
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise RuleError(f"{op} on {field!r} needs a list")
        try:
            members: Any = frozenset(value)
        except TypeError:
            members = list(value)
        if op == "in":
            return lambda pkt: (lambda a: a is not None and a in members)(pkt.get(field))
        return lambda pkt: (lambda a: a is not None and a not in members)(pkt.get(field))

    return lambda pkt: _apply_op(op, pkt.get(field), value)


def _compile_node(node: Any) -> Predicate:
    if not isinstance(node, dict) or not node:
        raise RuleError(f"condition must be a mapping, got {type(node).__name__}")
    if "all" in node or "any" in node:
        key = "all" if "all" in node else "any"
        children = node[key]
        if not isinstance(children, list) or not children:
            raise RuleError(f"'{key}' needs a non-empty list")
        preds = [_compile_node(child) for child in children]
        if key == "all":
            return lambda pkt: all(p(pkt) for p in preds)
        return lambda pkt: any(p(pkt) for p in preds)
    if "not" in node:
        inner = _compile_node(node["not"])
        return lambda pkt: not inner(pkt)
    if "field" in node:
        return _compile_leaf(node["field"], node.get("op", "eq"), node.get("value"))
    leaves = [_compile_leaf(k, "eq", v) for k, v in node.items()]
    return lambda pkt: all(p(pkt) for p in leaves)


def _requires_data(node: Any) -> bool:
    """True when the rule can never match a packet that carries no payload."""
    if not isinstance(node, dict):
        return False
    if "all" in node:
        return any(_requires_data(child) for child in node["all"] or [])
    if "any" in node:
        children = node["any"] or []
        return bool(children) and all(_requires_data(child) for child in children)
    if "not" in node:
        return False
    if "field" in node:
        if node.get("op", "eq") not in _POSITIVE_OPS:
            return False
        # ``eq: null`` / ``eq: false`` are true for a missing field.
        if node.get("op", "eq") == "eq" and not node.get("value"):
            return False
        return _needs_data(str(node["field"]))
    return any(_needs_data(str(k)) and bool(v) for k, v in node.items())


def _matched_conditions(node: Any, pkt: _Packet, out: List[Dict[str, Any]]) -> None:
    """Collect the leaf conditions that are true for *pkt* (explains a match)."""
    if not isinstance(node, dict) or len(out) >= 12:
        return
    for key in ("all", "any"):
        if key in node:
            for child in node[key] or []:
                _matched_conditions(child, pkt, out)
            return
    if "not" in node:
        return
    if "field" in node:
        leaves = [(node["field"], node.get("op", "eq"), node.get("value"))]
    else:
        leaves = [(k, "eq", v) for k, v in node.items()]
    for field, op, value in leaves:
        actual = pkt.get(str(field))
        if not _apply_op(op, actual, value):
            continue
        if isinstance(actual, (bytes, bytearray)):
            shown: Any = _excerpt(_text(actual), op, value)
        elif isinstance(actual, str):
            shown = actual[:200]
        else:
            shown = actual
        out.append({"field": field, "op": op, "expected": value, "actual": shown})


def _excerpt(text: str, op: str, value: Any) -> str:
    """The part of a payload around what matched, printable."""
    start = 0
    try:
        if op == "regex":
            m = re.search(str(value), text, re.IGNORECASE)
            start = m.start() if m else 0
        elif op == "contains":
            start = max(0, text.find(_unescape(value)))
    except re.error:
        start = 0
    begin = max(0, start - 24)
    piece = text[begin:start + 136]
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in piece)


_TEMPLATE_FIELD = re.compile(r"\{([A-Za-z_][\w.]*)\}")


class CompiledRule:
    """A validated rule, ready to evaluate."""

    __slots__ = ("rule", "rule_id", "severity", "confidence", "tags", "mitre", "description",
                 "message", "predicate", "needs_data", "count", "window", "track_by", "info")

    def __init__(self, rule: Dict[str, Any]) -> None:
        if not isinstance(rule, dict):
            raise RuleError("rule must be a mapping")
        self.rule = rule
        self.rule_id = str(rule.get("id", "unknown"))
        match = rule.get("match")
        if match is None:
            raise RuleError("missing 'match'")
        sev = str(rule.get("severity", "MEDIUM")).upper()
        if sev not in _SEVERITIES:
            raise RuleError(f"invalid severity {rule.get('severity')!r}")
        self.severity = Severity(sev)
        try:
            self.confidence = max(0.0, min(1.0, float(rule.get("confidence", 1.0))))
        except (TypeError, ValueError):
            raise RuleError(f"invalid confidence {rule.get('confidence')!r}") from None
        self.tags = [str(t) for t in (rule.get("tags") or [])]
        self.mitre = rule.get("mitre")
        self.description = str(rule.get("description") or f"Signature match: {self.rule_id}")
        self.message = rule.get("message")
        self.predicate = _compile_node(match)
        self.needs_data = _requires_data(match)

        self.count, self.window, self.track_by = 0, 0.0, "src_ip"
        thresh = rule.get("threshold")
        if thresh is not None:
            if not isinstance(thresh, dict):
                raise RuleError("'threshold' must be a mapping with count / seconds")
            try:
                self.count = int(thresh.get("count", 1))
                self.window = float(thresh.get("seconds", 60))
            except (TypeError, ValueError):
                raise RuleError("threshold count / seconds must be numbers") from None
            self.track_by = str(thresh.get("track_by", "src_ip"))
            if self.track_by not in _TRACK_BY:
                raise RuleError(f"threshold track_by must be one of {', '.join(_TRACK_BY)}")
            if self.count < 1 or self.window <= 0:
                raise RuleError("threshold needs count >= 1 and seconds > 0")

        info = {k: rule[k] for k in ("why", "response", "references") if rule.get(k)}
        self.info: Dict[str, Any] = info

    def render_message(self, pkt: _Packet) -> str:
        if not self.message:
            return self.description

        def _sub(m: "re.Match[str]") -> str:
            value = pkt.get(m.group(1))
            if value is None:
                return "?"
            if isinstance(value, (bytes, bytearray)):
                return _excerpt(_text(value), "eq", None)[:60]
            return str(value)[:120]
        return _TEMPLATE_FIELD.sub(_sub, str(self.message))


def compile_rules(rules: Iterable[Any]) -> Tuple[List[CompiledRule], List[str]]:
    """
    Compile *rules*; returns ``(compiled, problems)``.

    A rule that fails to compile is left out and described in *problems*, so
    one typo never takes the rest of the ruleset down with it.  Disabled
    rules (``enabled: false``) are skipped silently.
    """
    compiled: List[CompiledRule] = []
    problems: List[str] = []
    seen: Dict[str, int] = {}
    for index, rule in enumerate(rules or []):
        label = rule.get("id", f"#{index}") if isinstance(rule, dict) else f"#{index}"
        if isinstance(rule, dict) and rule.get("enabled", True) is False:
            continue
        # Legacy ``when:`` rules are only served by evaluate_packet().
        if isinstance(rule, dict) and "match" not in rule and "when" in rule:
            continue
        try:
            item = CompiledRule(rule)
        except RuleError as exc:
            problems.append(f"Rule {label}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 — a malformed rule must not stop the load
            problems.append(f"Rule {label}: {type(exc).__name__}: {exc}")
            continue
        if item.rule_id in seen:
            problems.append(f"Rule {label}: duplicate id (also rule #{seen[item.rule_id]}); keeping the first")
            continue
        seen[item.rule_id] = index
        compiled.append(item)
    return compiled, problems


def validate_rules(rules: Iterable[Any]) -> List[str]:
    """Every problem found in *rules* (compile errors, unknown keys, missing ids)."""
    rules = list(rules or [])
    _, problems = compile_rules(rules)
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        label = rule.get("id", f"#{index}")
        if "id" not in rule:
            problems.append(f"Rule #{index}: missing 'id'")
        if "match" not in rule and "when" not in rule:
            if not any(p.startswith(f"Rule {label}:") for p in problems):
                problems.append(f"Rule {label}: missing 'match'")
        unknown = sorted(set(rule) - _RULE_KEYS)
        if unknown:
            problems.append(f"Rule {label}: unknown key(s) {', '.join(unknown)}")
    return problems


# ---------------------------------------------------------------------------
# Signature detector
# ---------------------------------------------------------------------------

class SignatureDetector(BaseDetector):
    """
    Match packets against a YAML rule set.

    Each rule is evaluated against every packet.  If ``threshold`` is set
    the alert is only emitted once the rule has matched *count* times within
    *seconds* for the same tracking key (source IP by default); the counter
    then starts over, so a sustained burst alerts once per *count* hits.

    Args:
        rules: List of rule dictionaries (as returned by :func:`load_rules`).
    """

    def __init__(self, rules: List[Dict[str, Any]]) -> None:
        self._rules: List[Dict[str, Any]] = []
        self._compiled: List[CompiledRule] = []
        self.problems: List[str] = []
        # threshold tracking: {(rule_id, key): deque of timestamps}
        self._threshold_hits: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        # per-rule statistics
        self._hit_counts: Dict[str, int] = defaultdict(int)
        self._last_hit: Dict[str, float] = {}
        self._install(rules)

    def _install(self, rules: List[Dict[str, Any]]) -> None:
        self._rules = list(rules or [])
        self._compiled, self.problems = compile_rules(self._rules)
        for problem in self.problems:
            logger.warning("Signature rule skipped — %s", problem)

    @property
    def name(self) -> str:
        return "signature"

    def prune(self, now: float) -> None:
        windows = {r.rule_id: r.window for r in self._compiled if r.count}
        for key in [k for k, b in self._threshold_hits.items()
                    if not b or now - b[-1] > windows.get(k[0], 60.0)]:
            del self._threshold_hits[key]

    def update_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Hot-reload rules without restarting the detector."""
        self._install(rules)
        self._threshold_hits.clear()
        logger.info("SignatureDetector: reloaded %d rules", len(self._compiled))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def rule_stats(self) -> List[Dict[str, Any]]:
        """Every loaded rule with its hit count, for the dashboard and CLI."""
        active = {r.rule_id for r in self._compiled}
        out = []
        for index, rule in enumerate(self._rules):
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id", f"#{index}"))
            if rule.get("enabled", True) is False:
                status = "disabled"
            elif rule_id in active:
                status = "active"
            else:
                status = "error"
            out.append({
                "id": rule_id,
                "description": rule.get("description") or "",
                "severity": str(rule.get("severity", "MEDIUM")).upper(),
                "mitre": rule.get("mitre"),
                "tags": list(rule.get("tags") or []),
                "threshold": rule.get("threshold"),
                "status": status,
                "hits": self._hit_counts.get(rule_id, 0),
                "last_hit": self._last_hit.get(rule_id),
            })
        return out

    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        if not self._compiled:
            return
        # Most packets are bare ACKs: skip every rule that needs payload or
        # dissected fields without evaluating it.
        has_data = bool(meta.get("payload_bytes")) or any(k != "context" for k in layer7)
        pkt = _Packet(meta, layer7, flow)
        for rule in self._compiled:
            if rule.needs_data and not has_data:
                continue
            try:
                if not rule.predicate(pkt):
                    continue
                alert = self._fire(rule, pkt)
            except Exception as exc:  # noqa: BLE001 — one rule must not stop the others
                logger.error("Rule %r raised: %s", rule.rule_id, exc)
                continue
            if alert is not None:
                yield alert

    def _threshold_key(self, rule: CompiledRule, pkt: _Packet) -> str:
        meta = pkt.meta
        if rule.track_by == "dst_ip":
            return str(meta.get("dst_ip") or "")
        if rule.track_by == "pair":
            return f"{meta.get('src_ip')}>{meta.get('dst_ip')}"
        if rule.track_by == "flow":
            return pkt.flow.flow_id if pkt.flow is not None else f"{meta.get('src_ip')}>{meta.get('dst_ip')}"
        if rule.track_by == "global":
            return "*"
        return str(meta.get("src_ip") or "")

    def _fire(self, rule: CompiledRule, pkt: _Packet) -> Optional[Alert]:
        meta = pkt.meta
        now = meta.get("timestamp") or time.time()
        evidence: Dict[str, Any] = {}

        if rule.count:
            bucket = self._threshold_hits[(rule.rule_id, self._threshold_key(rule, pkt))]
            while bucket and (now - bucket[0]) > rule.window:
                bucket.popleft()
            bucket.append(now)
            if len(bucket) < rule.count:
                return None
            evidence["threshold"] = {
                "hits": len(bucket), "seconds": round(now - bucket[0], 1),
                "required": rule.count, "window": rule.window, "tracked_by": rule.track_by,
            }
            bucket.clear()  # the next alert needs a fresh run of hits

        self._hit_counts[rule.rule_id] += 1
        self._last_hit[rule.rule_id] = now

        matched: List[Dict[str, Any]] = []
        _matched_conditions(rule.rule.get("match"), pkt, matched)
        payload = meta.get("payload_bytes") or b""
        evidence["matched"] = matched
        if payload:
            evidence["payload_preview"] = payload[:256]
            evidence["payload_len"] = len(payload)
        l7 = _layer7_evidence(pkt.layer7)
        if l7:
            evidence["layer7"] = l7
        if rule.info:
            evidence["rule"] = dict(rule.info)

        return Alert(
            alert_type=AlertType.SIGNATURE,
            severity=rule.severity,
            message=rule.render_message(pkt),
            src_ip=meta.get("src_ip") or None,
            dst_ip=meta.get("dst_ip"),
            src_port=meta.get("src_port"),
            dst_port=meta.get("dst_port"),
            protocol=meta.get("protocol"),
            rule_id=rule.rule_id,
            flow_id=pkt.flow.flow_id if pkt.flow is not None else None,
            confidence=rule.confidence,
            tags=list(rule.tags),
            mitre_technique=rule.mitre,
            evidence=evidence,
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


def _layer7_evidence(layer7: dict) -> Dict[str, Any]:
    """Dissected fields worth keeping with an alert (no header dump, no context copy)."""
    out: Dict[str, Any] = {}
    for key, value in layer7.items():
        if key == "context":
            continue
        if isinstance(value, dict):
            value = {k: v for k, v in value.items()
                     if k not in ("headers", "ja3_string", "cipher_suites", "extensions") and v is not None}
        out[key] = value
    return out
