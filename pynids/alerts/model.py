"""
Core alert data model for PyNIDS.

Every detection result is represented as an Alert, carrying rich metadata
including severity, MITRE ATT&CK technique, confidence score, and
structured evidence for downstream correlation and storage.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Alert severity levels, ordered from least to most critical."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def numeric(self) -> int:
        """Integer value for comparison and filtering."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __ge__(self, other: "Severity") -> bool:
        return self.numeric >= other.numeric

    def __gt__(self, other: "Severity") -> bool:
        return self.numeric > other.numeric

    def __le__(self, other: "Severity") -> bool:
        return self.numeric <= other.numeric

    def __lt__(self, other: "Severity") -> bool:
        return self.numeric < other.numeric


class AlertType(str, Enum):
    """Classification of how the alert was generated."""

    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    THREAT_INTEL = "threat_intel"
    CORRELATION = "correlation"


@dataclass
class Alert:
    """
    A single detection event raised by any detector in the pipeline.

    Attributes:
        alert_type:      Which category of detector raised this alert.
        severity:        Urgency level (LOW → CRITICAL).
        message:         Human-readable description of the event.
        src_ip:          Source IP address of the triggering packet/flow.
        dst_ip:          Destination IP address.
        src_port:        Source TCP/UDP port.
        dst_port:        Destination TCP/UDP port.
        protocol:        Transport protocol ('tcp', 'udp', 'icmp', …).
        rule_id:         Identifier of the matched rule (signature alerts).
        flow_id:         MD5 key of the 5-tuple flow this packet belongs to.
        confidence:      Detector confidence from 0.0 (speculative) to 1.0 (certain).
        tags:            Free-form taxonomy tags (e.g. ['recon', 'portscan']).
        mitre_technique: MITRE ATT&CK technique ID (e.g. 'T1046').
        evidence:        Arbitrary key/value evidence payload for investigation.
        alert_id:        UUID4 unique identifier generated at creation time.
        timestamp:       Unix epoch float when the alert was raised.
    """

    alert_type: AlertType
    severity: Severity
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    rule_id: Optional[str] = None
    flow_id: Optional[str] = None
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the alert to a plain dictionary (JSON-safe types)."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "severity_numeric": self.severity.numeric,
            "message": self.message,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "rule_id": self.rule_id,
            "flow_id": self.flow_id,
            "confidence": self.confidence,
            "tags": self.tags,
            "mitre_technique": self.mitre_technique,
            "evidence": {
                k: v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
                for k, v in self.evidence.items()
            },
        }

    @property
    def dedup_key(self) -> str:
        """Key used for alert deduplication within a time window."""
        return f"{self.rule_id or self.alert_type.value}|{self.src_ip}|{self.dst_ip}|{self.dst_port}"
