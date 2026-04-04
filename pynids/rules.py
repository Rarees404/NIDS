from typing import Any, Dict, List

import yaml


def load_rules(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", [])


class SignatureDetector:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def evaluate_packet(self, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            when = rule.get("when", {})
            if self._matches(when, meta):
                alerts.append({
                    "type": "signature",
                    "rule_id": rule.get("id", "unknown"),
                    "message": rule.get("description", "signature match"),
                    "meta": meta,
                })
        return alerts

    def _matches(self, when: Dict[str, Any], meta: Dict[str, Any]) -> bool:
        for key, expected in when.items():
            if key == "payload_contains":
                payload = meta.get("payload_bytes", b"")
                if isinstance(expected, str):
                    try:
                        expected_bytes = expected.encode()
                    except Exception:
                        return False
                else:
                    expected_bytes = bytes(expected)
                if expected_bytes not in payload:
                    return False
            else:
                if meta.get(key) != expected:
                    return False
        return True




