"""
Map alerts to the coarse "kinds" shown by every UI (terminal dashboard,
web dashboard, menu bar app, widget), so they all group events the same way.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Union

from .model import Alert

KINDS = (
    "threat", "attack", "webrtc", "localhost", "doh", "tracker",
    "beacon", "websocket", "quic", "prefetch", "other",
)

KIND_LABELS: Dict[str, str] = {
    "threat": "Threat intel",
    "attack": "Attacks & anomalies",
    "webrtc": "WebRTC / IP leaks",
    "localhost": "Localhost probes",
    "doh": "Encrypted DNS",
    "tracker": "Trackers",
    "beacon": "Beacons & pixels",
    "websocket": "WebSockets",
    "quic": "QUIC / HTTP-3",
    "prefetch": "DNS prefetch",
    "other": "Other",
}


def classify_parts(rule_id: str, tags: Iterable[str], alert_type: str) -> str:
    rid = (rule_id or "").upper()
    tags = set(tags or ())
    if alert_type == "threat_intel":
        return "threat"
    if "webrtc" in tags or rid.startswith("STEALTH-WEBRTC"):
        return "webrtc"
    if "localhost_probe" in tags or "localhost_scan" in tags or rid.startswith("STEALTH-LOCALHOST"):
        return "localhost"
    if "doh" in tags or "encrypted_dns" in tags or rid == "STEALTH-ENCRYPTED-DNS":
        return "doh"
    if "quic" in tags or rid.startswith("STEALTH-QUIC"):
        return "quic"
    if "websocket" in tags or rid.startswith("STEALTH-WEBSOCKET"):
        return "websocket"
    if "tracker" in tags or rid.startswith("STEALTH-TRACKER"):
        return "tracker"
    if "beacon" in tags or rid.startswith("STEALTH-BEACON"):
        return "beacon"
    if "dns_prefetch" in tags or rid.startswith("STEALTH-DNS-PREFETCH"):
        return "prefetch"
    if alert_type in ("signature", "anomaly", "behavioral", "correlation"):
        return "attack"
    return "other"


def classify(alert: Union[Alert, Dict[str, Any]]) -> str:
    if isinstance(alert, Alert):
        return classify_parts(alert.rule_id or "", alert.tags, alert.alert_type.value)
    return classify_parts(
        alert.get("rule_id") or "", alert.get("tags") or (), alert.get("alert_type") or ""
    )
