"""
Configuration management for PyNIDS.

Loads a YAML configuration file and deep-merges it with the default
configuration, so any unspecified key falls back to a safe default
without requiring a fully-specified config file.

The resulting config dict is used throughout the engine and CLI to
instantiate detectors, outputs, and the flow tracker.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "anomaly": {
        "ewma_alpha": 0.3,
        "sigma_threshold": 4.0,
        "window_seconds": 10,
    },
    "scan": {
        "horizontal_threshold": 20,
        "horizontal_window": 60,
        "vertical_threshold": 15,
        "vertical_window": 60,
    },
    "brute_force": {
        "threshold": 10,
        "window": 30,
        "ports": [21, 22, 23, 25, 110, 143, 389, 636, 3389, 5900],
    },
    "behavioral": {
        "dns_entropy_threshold": 3.5,
        "dns_length_threshold": 50,
        "exfil_threshold_bytes": 10 * 1024 * 1024,
        "beacon_min_connections": 6,
        "beacon_cv_threshold": 0.20,
    },
    "flow": {
        "max_flows": 100_000,
        "idle_timeout": 300,
    },
    "intel": {
        "enabled": False,
        "bad_ips_file": None,
        "malicious_domains_file": None,
    },
    "alert_manager": {
        "dedup_window": 60,
        "correlation_window": 120,
        "correlation_threshold": 3,
        "min_severity": "LOW",
        "suppression": [],
    },
    "outputs": {
        "console": {
            "enabled": True,
            "min_severity": "LOW",
            "show_evidence": False,
        },
        "json_file": {
            "enabled": False,
            "path": "pynids-alerts.json",
            "max_bytes": 10 * 1024 * 1024,
            "backup_count": 5,
        },
        "sqlite": {
            "enabled": False,
            "path": "pynids-alerts.db",
        },
        "syslog": {
            "enabled": False,
            "host": "localhost",
            "port": 514,
            "protocol": "udp",
        },
    },
}


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> Dict[str, Any]:
    """
    Load *path* and deep-merge it with :data:`DEFAULT_CONFIG`.

    Args:
        path: Path to a YAML configuration file.

    Returns:
        Merged configuration dictionary.

    Raises:
        FileNotFoundError: If *path* does not exist.
        yaml.YAMLError:    If the file is not valid YAML.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        user_data = yaml.safe_load(f) or {}

    return _deep_merge(DEFAULT_CONFIG, user_data)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge *override* into a copy of *base*.

    Scalar values in *override* replace those in *base*.
    Dicts are merged recursively.  Lists are replaced wholesale.
    """
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
