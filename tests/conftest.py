"""
Shared test fixtures for PyNIDS test suite.
"""
from __future__ import annotations

import time
import pytest
from typing import Any, Dict, List

from pynids.alerts.model import Alert, AlertType, Severity
from pynids.alerts.manager import AlertManager, BaseOutput
from pynids.detection.signature import SignatureDetector
from pynids.detection.anomaly import AnomalyDetector, PortScanDetector, BruteForceDetector
from pynids.detection.behavioral import (
    DnsTunnelingDetector,
    HttpAttackDetector,
    DataExfiltrationDetector,
    BeaconingDetector,
)
from pynids.flow.tracker import FlowTracker, Flow, FlowState


# ---------------------------------------------------------------------------
# Packet meta factories
# ---------------------------------------------------------------------------

def make_meta(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "tcp",
    payload: bytes = b"",
    tcp_flags: int = 0,
    timestamp: float | None = None,
) -> Dict[str, Any]:
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload_bytes": payload,
        "tcp_flags": tcp_flags,
        "timestamp": timestamp or time.time(),
        "ip_ttl": 64,
        "packet_len": 100 + len(payload),
    }


# ---------------------------------------------------------------------------
# Alert collection helper
# ---------------------------------------------------------------------------

class AlertCollector(BaseOutput):
    """Collects emitted alerts for inspection in tests."""

    def __init__(self) -> None:
        self.alerts: List[Alert] = []

    def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)

    @property
    def count(self) -> int:
        return len(self.alerts)

    def of_type(self, alert_type: AlertType) -> List[Alert]:
        return [a for a in self.alerts if a.alert_type == alert_type]

    def of_severity(self, severity: Severity) -> List[Alert]:
        return [a for a in self.alerts if a.severity == severity]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def collector() -> AlertCollector:
    return AlertCollector()


@pytest.fixture
def alert_manager(collector: AlertCollector) -> AlertManager:
    mgr = AlertManager(dedup_window=0)  # disable dedup for tests
    mgr.register_output(collector)
    return mgr


@pytest.fixture
def flow_tracker() -> FlowTracker:
    return FlowTracker()
