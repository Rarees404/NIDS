"""Plain-English alert guidance."""
from pynids.alerts.guide import ACT, CHECK, HARMLESS, PRIVACY, describe


def _alert(**kw):
    base = {"alert_type": "behavioral", "severity": "MEDIUM", "message": "m", "tags": [],
            "evidence": {}, "context": {}}
    base.update(kw)
    return base


def test_every_guide_has_all_parts():
    g = describe(_alert(rule_id="STEALTH-QUIC-INITIAL", evidence={"sni": "www.youtube.com"}))
    assert set(g) == {"summary", "meaning", "verdict", "next_steps", "details"}
    assert "www.youtube.com" in g["summary"] and g["verdict"] == HARMLESS


def test_localhost_probe_depends_on_who_initiated():
    browser = describe(_alert(rule_id="STEALTH-LOCALHOST-PROBE", dst_port=9222,
                              evidence={"initiator": "browser", "destination_class": "loopback"},
                              context={"app": "Google Chrome"}))
    assert browser["verdict"] == CHECK and "Google Chrome" in browser["summary"]
    assert ("Port", "port 9222 (Chrome's remote debugging)") in browser["details"]
    unknown = describe(_alert(rule_id="STEALTH-LOCALHOST-PROBE", dst_port=1337,
                              evidence={"initiator": "unidentified", "destination_class": "loopback"}))
    assert unknown["verdict"] == HARMLESS and "lsof" in " ".join(unknown["next_steps"])


def test_beaconing_to_bare_ip_is_worth_checking():
    g = describe(_alert(tags=["beaconing"], dst_ip="45.33.32.156",
                        evidence={"mean_interval_seconds": 600, "hostname_known": False}))
    assert g["verdict"] == CHECK and "every 10 minutes" in g["summary"]


def test_private_relay_and_threat_intel():
    relay = describe(_alert(rule_id="STEALTH-ENCRYPTED-DNS",
                            evidence={"method": "DoH (DNS-over-HTTPS)", "resolver": "mask.icloud.com"}))
    assert "Private Relay" in relay["summary"]
    ti = describe(_alert(alert_type="threat_intel", severity="HIGH",
                         evidence={"matched_indicator": "198.51.100.7", "category": "botnet"}))
    assert ti["verdict"] == ACT and "198.51.100.7" in ti["summary"]


def test_tracker_is_privacy_and_unknown_rules_fall_back():
    assert describe(_alert(rule_id="STEALTH-TRACKER", evidence={"host": "x.doubleclick.net",
                                                                "category": "Google DoubleClick"}))["verdict"] == PRIVACY
    assert describe(_alert(rule_id="SIG-1234", message="Custom rule hit"))["summary"] == "Custom rule hit"
