"""
PyNIDS — Enterprise Network Intrusion Detection System.

A production-grade NIDS built on Scapy with:
  - Multi-layer detection (signature, anomaly, behavioral, threat-intel)
  - Stateful flow tracking and protocol dissection
  - Alert deduplication, suppression, and correlation
  - Multiple output backends (console, JSON, SQLite, syslog)
  - Hot-reloadable signature rules

Quick start::

    from pynids.engine import DetectionEngine
    from pynids.config import load_config

    cfg = load_config("configs/enterprise.yaml")
    engine = DetectionEngine(config=cfg, rules_path="rules/enterprise_rules.yaml")
    # engine.process_packet(meta_dict)
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
