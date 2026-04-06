from pynids.detection.signature import SignatureDetector


def test_signature_detector_matches_port_and_payload():
    rules = [
        {
            "id": "TEST_RULE",
            "description": "Test rule matches dst 80 and payload",
            "when": {"dst_port": 80, "payload_contains": "hello"},
        }
    ]
    det = SignatureDetector(rules)
    meta = {
        "protocol": "tcp",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "src_port": 12345,
        "dst_port": 80,
        "payload_bytes": b"say hello world",
    }
    alerts = det.evaluate_packet(meta)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TEST_RULE"


