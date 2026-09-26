"""
PyNIDS — Enterprise Network Intrusion Detection System.

A production-grade NIDS built on Scapy with:
  - Multi-layer detection (signature, anomaly, behavioral, threat-intel)
  - Stateful flow tracking and protocol dissection
  - Alert deduplication, suppression, and correlation
  - Multiple output backends (console, JSON, SQLite, syslog)
  - Hot-reloadable signature rules
  - X-Ray mode: hidden browser activity, per-app attribution, QUIC/TLS SNI
  - macOS daemon, local API, web dashboard, menu bar app and widget

Quick start::

    from pynids.engine import DetectionEngine
    from pynids.config import load_config

    cfg = load_config("configs/enterprise.yaml")
    engine = DetectionEngine(config=cfg, rules_path="rules/enterprise_rules.yaml")
    # engine.process_packet(meta_dict)
"""

import warnings

__version__ = "2.0.0"

# Scapy's optional TLS layer imports a deprecated finite-field DH API from
# cryptography; the warning is noise for PyNIDS users.
warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")

__all__ = ["__version__"]
