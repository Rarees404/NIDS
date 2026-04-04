<div align="center">

# 🛡️ PyNIDS

### Enterprise-Grade Python Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

A production-ready, pure-Python NIDS built on [Scapy](https://scapy.net/) with multi-layer detection —  
signature, statistical anomaly, behavioral, and threat-intelligence — all in one unified pipeline.

</div>

---

## ✨ Features

| Category | Capability |
|---|---|
| 📡 **Capture** | Live interface sniffing (`AsyncSniffer`) and PCAP/PCAPNG replay |
| 🔬 **Dissection** | Pure-Python HTTP, DNS, TLS (JA3), SSH, SMTP parsers |
| 🌊 **Flow Tracking** | Stateful 5-tuple connection table with TCP state machine |
| 📝 **Signature Engine** | YAML declarative rules — bool combinators, 13 operators, per-rule thresholds, hot-reload |
| 📈 **Anomaly Detection** | EWMA volumetric spikes, horizontal/vertical port scans, brute-force |
| 🧠 **Behavioral Detection** | DNS tunneling (entropy), HTTP attacks (SQLi/XSS/traversal), data exfiltration, C2 beaconing |
| 🌐 **Threat Intelligence** | Local CIDR-based bad-IP feeds + malicious domain suffix matching |
| 🔔 **Alert Management** | Deduplication, IP/CIDR suppression allowlists, multi-vector correlation |
| 💾 **Output Backends** | Console (Rich), rotating JSON file, SQLite, Syslog (UDP/TCP) |
| 🖥️ **CLI** | Five commands: `live`, `pcap`, `query`, `validate`, `--version` |

---

## 🚀 Quick Start

### 1. Install

```bash
pip install -e ".[dev]"    # Development install with test dependencies

# Or production install from the project root:
pip install .
```

**Dependencies:** `scapy>=2.5`, `PyYAML>=6.0`, `click>=8.1`, `rich>=13.0`

> **Note:** Live capture requires **root/administrator privileges** for raw socket access.

### 2. Analyse a PCAP file

```bash
pynids pcap --file capture.pcap --rules rules/enterprise_rules.yaml
```

### 3. Monitor live traffic

```bash
sudo pynids live --iface en0 --rules rules/enterprise_rules.yaml
```

### 4. Use the enterprise configuration

```bash
sudo pynids live --iface eth0 \
     --config configs/enterprise.yaml \
     --rules  rules/enterprise_rules.yaml \
     --sqlite  alerts.db
```

---

## 📦 Project Structure

```
PyNIDS/
├── pyproject.toml               # Build config & dependencies
├── configs/
│   ├── default.yaml             # Minimal defaults
│   └── enterprise.yaml          # Full tunable config (annotated)
├── rules/
│   ├── sample_rules.yaml        # Minimal example
│   └── enterprise_rules.yaml    # 20+ production rules (MITRE-tagged)
├── intel/
│   ├── known_bad_ips.yaml       # CIDR bad-IP feed
│   └── malicious_domains.yaml   # Malicious domain/suffix blocklist
├── tests/                       # pytest suite (8 test files)
└── pynids/
    ├── engine.py                # DetectionEngine orchestrator
    ├── sniffer.py               # Packet capture + normalisation
    ├── cli.py                   # Click CLI
    ├── alerts/                  # Alert model, manager, output backends
    ├── detection/               # Signature, anomaly, behavioral detectors
    ├── flow/                    # FlowTracker
    ├── intel/                   # ThreatIntel
    └── protocols/               # HTTP/DNS/TLS/SSH/SMTP dissectors
```

---

## 🔧 CLI Reference

### `pynids live` — Real-time capture

```bash
sudo pynids live \
  --iface en0 \                         # Network interface (required)
  --rules rules/enterprise_rules.yaml \ # Signature rules
  --config configs/enterprise.yaml \    # YAML config
  --bpf "not port 22" \                 # BPF capture filter
  --sqlite alerts.db \                  # Persist to SQLite
  --output text \                       # text | json
  --min-severity MEDIUM \               # LOW | MEDIUM | HIGH | CRITICAL
  --verbose                             # Show evidence fields
```

### `pynids pcap` — PCAP analysis

```bash
pynids pcap \
  --file capture.pcap \
  --rules rules/enterprise_rules.yaml \
  --output json | jq 'select(.severity=="CRITICAL")'
```

### `pynids query` — Query SQLite alert store

```bash
pynids query --db alerts.db --min-severity HIGH
pynids query --db alerts.db --src-ip 10.0.0.5 --type signature --json
```

### `pynids validate` — Validate rules/config YAML

```bash
pynids validate rules/enterprise_rules.yaml
pynids validate configs/enterprise.yaml --type config
```

---

## 📜 Writing Signature Rules

Rules live in any YAML file passed with `--rules`. Full syntax:

```yaml
rules:
  - id: "SIG-EXP-001"
    description: "SQL injection pattern in HTTP URI"
    severity: CRITICAL          # LOW | MEDIUM | HIGH | CRITICAL
    confidence: 0.88
    mitre: "T1190"
    tags: [sqli, webapp, initial_access]
    match:
      all:
        - {field: protocol, op: eq, value: tcp}
        - {field: dst_port, op: in, value: [80, 8080, 8000]}
        - {field: layer7.http.sqli_suspect, op: eq, value: true}
    threshold:                  # Optional: alert only after N hits in T seconds
      count: 3
      seconds: 60
    action: alert
```

### Available Operators

| Operator | Description |
|---|---|
| `eq` / `ne` | Equality / not equal |
| `lt` / `gt` / `lte` / `gte` | Numeric comparisons |
| `in` / `not_in` | List membership |
| `contains` | Substring (string or bytes) |
| `startswith` | String prefix |
| `regex` | Regular expression (`re.search`, case-insensitive) |
| `exists` | Field present and not None |

### Dot-notation Layer-7 Fields

```
layer7.http.uri              layer7.http.user_agent
layer7.http.sqli_suspect     layer7.http.xss_suspect
layer7.http.scanner_ua       layer7.http.path_traversal_suspect
layer7.dns.query_name        layer7.dns.query_type
layer7.dns.name_entropy      layer7.tls.sni
layer7.tls.ja3               layer7.ssh.software
```

---

## ⚙️ Configuration

Copy `configs/enterprise.yaml` and edit the sections you need:

```yaml
# Statistical anomaly thresholds
anomaly:
  ewma_alpha: 0.3        # Smoothing factor (0=slow, 1=instant)
  sigma_threshold: 3.5   # Std devs above EWMA → alert

# Port scan detection
scan:
  horizontal_threshold: 15   # Unique dst IPs on same port → host sweep alert
  vertical_threshold: 12     # Unique ports on same dst → port scan alert

# Brute-force detection
brute_force:
  threshold: 8
  window: 30
  ports: [22, 3389, 5900]

# Data exfiltration
behavioral:
  exfil_threshold_bytes: 10485760  # 10 MiB per flow

# Alert deduplication + correlation
alert_manager:
  dedup_window: 60           # Suppress duplicates for 60 s
  correlation_threshold: 3   # 3 distinct signatures from one IP → correlation alert

# Suppression allowlist
# suppression:
#   - rule_id: "SIG-LAT-001"
#     src_cidr: "10.10.0.0/16"   # Known-good admin VLAN
```

---

## 🗂️ Threat Intelligence Feeds

### Bad IP feed (`intel/known_bad_ips.yaml`)

```yaml
entries:
  - cidr: "185.220.101.0/24"
    category: tor_exit
    severity: MEDIUM
    description: "Known Tor exit relay range"

  - cidr: "198.51.100.1/32"
    category: c2
    severity: HIGH
    description: "Known C2 server"
```

### Malicious domain feed (`intel/malicious_domains.yaml`)

```yaml
entries:
  - domain: "malware-c2.example"
    category: c2
    severity: HIGH
    description: "Active C2 domain"

  - domain: ".dyndns.org"    # Leading dot = suffix match (any subdomain)
    category: dyndns
    severity: MEDIUM
    description: "Dynamic DNS service frequently abused for C2"
```

---

## 📊 Alert Structure

Every detection event is a structured `Alert` with rich metadata:

```json
{
  "alert_id": "3f82a2e1-...",
  "timestamp": 1712000000.123,
  "alert_type": "signature",
  "severity": "CRITICAL",
  "severity_numeric": 4,
  "message": "SQL injection pattern in HTTP request URI",
  "src_ip": "192.168.1.50",
  "dst_ip": "10.0.0.10",
  "dst_port": 80,
  "protocol": "tcp",
  "rule_id": "SIG-EXP-001",
  "confidence": 0.88,
  "tags": ["sqli", "webapp", "initial_access"],
  "mitre_technique": "T1190",
  "evidence": {
    "uri": "/products?id=1 UNION SELECT * FROM users--",
    "method": "GET",
    "host": "shop.example.com"
  }
}
```

Alert types: `signature`, `anomaly`, `behavioral`, `threat_intel`, `correlation`

---

## 🧪 Running Tests

```bash
# Install dev dependencies first
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=pynids --cov-report=term-missing

# Run a specific test file
pytest tests/test_behavioral.py -v
```

---

## 🗺️ Detection Coverage (MITRE ATT&CK)

| Technique | ID | Detector |
|---|---|---|
| Active Scanning | T1595 | Signature (`scanner_ua`) |
| Network Service Discovery | T1046 | `PortScanDetector` |
| Brute Force | T1110 | `BruteForceDetector` |
| Exploit Public-Facing App | T1190 | Signature + `HttpAttackDetector` |
| Command Scripting — Bash | T1059.004 | Signature (reverse shells) |
| Command Scripting — Python | T1059.006 | Signature |
| Command Scripting — PowerShell | T1059.001 | Signature |
| Application Layer Protocol — DNS | T1071.004 | `DnsTunnelingDetector` |
| Application Layer Protocol — HTTP | T1071.001 | Signature + Behavioral |
| Application Layer Protocol (C2) | T1071 | `BeaconingDetector` + Signature |
| Data Exfiltration Over C2 | T1041 | `DataExfiltrationDetector` |
| Exfil Over Alternative Protocol | T1048.003 | Signature (DNS TXT) |
| Remote Services — SMB | T1021.002 | Signature |
| Remote Services — RDP | T1021.001 | Signature |
| Endpoint Denial of Service | T1498 | `AnomalyDetector` |

---

## 🔌 Embedding PyNIDS as a Library

```python
from pynids.engine import DetectionEngine
from pynids.config import load_config
from pynids.intel.threat_intel import ThreatIntel
from pynids.alerts.manager import AlertManager
from pynids.alerts.outputs.json_file import JsonFileOutput

# Load config and build engine
cfg = load_config("configs/enterprise.yaml")

mgr = AlertManager(dedup_window=60)
mgr.register_output(JsonFileOutput("alerts.json"))

intel = ThreatIntel(
    bad_ips_path="intel/known_bad_ips.yaml",
    malicious_domains_path="intel/malicious_domains.yaml",
)

engine = DetectionEngine(
    config=cfg,
    rules_path="rules/enterprise_rules.yaml",
    intel=intel,
    alert_manager=mgr,
)

# Process a packet meta dict (e.g., from sniffer.packet_to_meta):
alerts = engine.process_packet(meta)

# Hot-reload rules without stopping:
engine.reload_rules()

# Session statistics:
print(engine.stats)

# Flush outputs on exit:
mgr.close()
```

---

## 📋 Requirements

| Dependency | Version | Purpose |
|---|---|---|
| [scapy](https://scapy.net/) | ≥ 2.5.0 | Packet capture and basic parsing |
| [PyYAML](https://pyyaml.org/) | ≥ 6.0.0 | Config and rule file loading |
| [click](https://click.palletsprojects.com/) | ≥ 8.1.0 | CLI framework |
| [rich](https://github.com/Textualize/rich) | ≥ 13.0.0 | Terminal output formatting |

**Dev only:** `pytest>=7.4`, `pytest-cov>=4.1`

---

## 📄 License

This project is distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 📚 Further Reading

- [`documentation.md`](documentation.md) — Deep technical reference covering every module, data flow, design decisions, and internal APIs.
- [MITRE ATT&CK](https://attack.mitre.org/) — Framework referenced by all detection rules and alerts.
- [Scapy documentation](https://scapy.readthedocs.io/) — Underlying packet capture library.
