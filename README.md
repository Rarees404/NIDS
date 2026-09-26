<div align="center">

# 🛡️ PyNIDS

### Network intrusion detection and privacy X-Ray for your Mac

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()

PyNIDS watches your real network traffic and tells you what is happening in it: attacks,
connections to known-malicious hosts, and the things browsers and apps do quietly that never
show up in DevTools, such as trackers, WebRTC IP leaks, webpages port-scanning your
localhost, and DNS lookups hidden inside HTTPS. It shows **which app** made each connection
and **where** it went. It runs as an always-on background service with a web dashboard, a
menu bar app, a desktop widget, and native notifications.

</div>

---

## ✨ Features

| Category | Capability |
|---|---|
| 📡 **Capture** | Live sniffing of the active interface **and** loopback; follows Wi-Fi ↔ Ethernet ↔ VPN switches automatically |
| 🔬 **Dissection** | HTTP, DNS (queries **and answers**), TLS (SNI, ALPN, ECH, JA3), SSH, SMTP, STUN, QUIC |
| 🔓 **Encrypted-traffic visibility** | Decrypts **QUIC Initial packets** to read the hostname of every HTTP/3 connection; reassembles post-quantum TLS ClientHellos split across TCP segments |
| 🧩 **App attribution** | Every packet and alert is tagged with the owning app (Chrome helper processes fold into "Google Chrome") |
| 🌍 **Enrichment** | Hostnames learned passively from DNS/SNI, plus offline GeoIP + ASN (DB-IP Lite) |
| 📝 **Signature engine** | YAML rules with boolean combinators, 13 operators, thresholds, hot-reload |
| 📈 **Anomaly & behavioral** | Volumetric spikes, port scans, brute force, DNS tunnelling, SQLi/XSS, exfiltration, C2 beaconing |
| 🩻 **X-Ray (privacy)** | WebRTC IP leaks, localhost/LAN port-scans by webpages, QUIC/HTTP-3, WebSockets, beacons, prefetch storms, trackers (4,000+ domains), **encrypted DNS (DoH/DoT/DoQ)** |
| 🌐 **Live threat intel** | abuse.ch Feodo & URLhaus, Spamhaus DROP (v4+v6), Tor exits, Disconnect trackers, DoH resolver lists, all refreshed automatically |
| 🛑 **Blocking** | One-click or automatic blocking through macOS's built-in `pf` firewall, with guard rails and expiry |
| 🔔 **Notifications** | Native macOS banners for important alerts, rate-limited and coalesced |
| 🤖 **Explain with Claude** | Plain-English verdict and next steps for any alert (optional, your API key) |
| 🖥️ **Web dashboard** | Live throughput, events timeline, world map, per-app table, searchable event stream, block/unblock, feed status |
| 📍 **Menu bar + widget** | Native SwiftUI menu bar app and a small/medium/large desktop widget |
| 🔐 **Decryption workflow** | Launch a browser with TLS key logging, record traffic, and list decrypted HTTPS/HTTP-2/HTTP-3 requests |

---

## 🚀 Quick Start (macOS)

```bash
git clone <this repo> ~/NIDS && cd ~/NIDS
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip            # macOS ships an old pip that can't install this project
pip install -e ".[all]"              # core + GeoIP + Claude

# 1. Always-on protection: installs a LaunchDaemon that starts at boot
sudo .venv/bin/pynids daemon install

# 2. World map + country/ASN enrichment (free DB-IP Lite, ~70 MB)
sudo .venv/bin/pynids geoip download && sudo .venv/bin/pynids daemon restart

# 3. See it
pynids open                          # web dashboard → http://127.0.0.1:8787
pynids status                        # one-screen summary in the terminal
pynids app                           # build + install the menu bar app and widget
```

Optional:

```bash
sudo pynids ai set-key               # enable "Explain with Claude"
pynids intel update                  # feeds refresh every 6 h anyway
```

> **Why sudo?** Reading raw packets (`/dev/bpf*`), seeing every process's sockets, and
> managing `pf` all require root. The daemon runs as root under launchd; the dashboard,
> CLI, menu bar app, and widget run as you and talk to it over `127.0.0.1`.

To remove everything: `sudo pynids daemon uninstall` (lifts all blocks too), then delete
`~/Applications/PyNIDS.app` and `/Library/Application Support/PyNIDS`.

### Quick start without the daemon

```bash
sudo pynids xray --iface en0         # live terminal X-Ray dashboard
sudo pynids live --iface en0 --rules rules/enterprise_rules.yaml
pynids pcap --file capture.pcap      # analyse a capture you recorded
```

---

## 🖥️ The Always-On Service

`pynids daemon install` writes `/Library/LaunchDaemons/com.pynids.daemon.plist` and starts it.
The daemon:

* captures the interface carrying your default route **plus** `lo0` (so it can see webpages
  probing `127.0.0.1`), restarting capture when you change networks
* runs every detector, tags events with app, hostname, country, and network owner
* stores events in `/Library/Application Support/PyNIDS/events.db` (SQLite, full-text search)
* serves the dashboard and API on `http://127.0.0.1:8787`
* posts notifications for HIGH and CRITICAL alerts
* refreshes threat-intel feeds every 6 hours
* optionally auto-blocks confirmed-malicious IPs

| Command | What it does |
|---|---|
| `sudo pynids daemon install [--rules FILE] [--record]` | Install and start at boot |
| `sudo pynids daemon restart` | Apply config changes |
| `sudo pynids daemon uninstall` | Stop, remove, and lift all blocks |
| `pynids daemon logs -f` | Follow `/Library/Logs/PyNIDS/daemon.log` |
| `pynids status` | Health, threat level, traffic, top apps, latest alert |
| `pynids open` | Open the dashboard |

Configuration lives in `/Library/Application Support/PyNIDS/config.yaml` (created on install,
fully commented; the template is [`pynids/service/default_config.yaml`](pynids/service/default_config.yaml)).

### Web dashboard

`pynids open` shows:

* **Overview**: hidden events, threats, trackers, leaks and probes, encrypted DNS, and countries reached; live throughput; events per minute
* **Network**: world map of every remote endpoint, sized by bytes and marked when it raised an alert
* **Apps**: which app talks to how many endpoints, how much it sends and receives, and to which hosts and countries
* **Events**: live, filterable, full-text-searchable stream. Click an event for its evidence, app, location, **Explain with Claude**, and **Block IP**
* **Protection**: blocked IPs (unblock with one click) and threat-intel feed status

### Menu bar app & desktop widget

```bash
pynids app          # = macos/build.sh --install
```

This builds a native SwiftUI app with only the Xcode Command Line Tools and installs it to
`~/Applications`. The menu bar shield changes colour with the threat level and shows the
threat count. Its popover has live stats, a throughput sparkline, recent alerts (hover to
block), the busiest apps, a notification toggle, and launch-at-login. To add the widget,
right-click the desktop → **Edit Widgets** → **PyNIDS** (small, medium, or large).

Prefer [SwiftBar](https://github.com/swiftbar/SwiftBar)? Symlink
[`macos/swiftbar/pynids.5s.py`](macos/swiftbar/pynids.5s.py) into its plugin folder.

### Blocking with pf

```bash
pynids block add 203.0.113.50 --ttl 3600
pynids block list
pynids block remove 203.0.113.50
```

Blocks live in the pf sub-anchor `com.apple/250.PyNIDS`, which the stock macOS `pf.conf`
already evaluates, so no system file is edited. They expire automatically. Private,
loopback, link-local, multicast, gateway, and DNS-server addresses are **never** blocked.
Automatic blocking (`response.auto_block: true`) only acts on threat-intel matches and
correlated multi-vector attacks, never on privacy events. It also has a `dry_run` mode.

### Explain with Claude

`sudo pynids ai set-key` stores an Anthropic API key (mode 0600) for the daemon. After that,
**Explain with Claude** in the dashboard (or `pynids ai explain <alert-id>`) sends that
single alert, with its evidence and enrichment, to Claude Opus 5. You get back a verdict
(Benign / Privacy concern / Suspicious / Malicious), what happened, why it matters, and what
to do. Explanations are cached per alert. Nothing is sent unless you click.

### Seeing inside HTTPS: key logging + decryption

```bash
pynids keylog --browser chrome              # separate Chrome profile that logs TLS keys
sudo pynids daemon install --record         # keep a rolling 500 MB window of raw traffic
pynids decrypt                              # list decrypted HTTPS / HTTP-2 / HTTP-3 requests
pynids decrypt --wireshark                  # open the latest capture in Wireshark, keys loaded
```

Chrome, Brave, Edge, and Firefox honour `SSLKEYLOGFILE`; Safari does not. The key log
decrypts that browser's traffic, so it is created readable only by you. Delete it when
you are done. `decrypt` needs `tshark` (`brew install --cask wireshark`).

---

## 🔐 Privacy & Security Model

* All capture, storage, and analysis happens **on your Mac**. The only outbound requests are
  feed/GeoIP downloads and, if you click it, **Explain with Claude**.
* The API binds to `127.0.0.1` only and enforces a **Host-header allowlist** (defeats DNS
  rebinding), a **random token** for every data route, an **Origin check** on state-changing
  requests, and sends **no CORS headers**. A malicious webpage therefore cannot read your
  events or block IPs through it.
* `/api/widget` is the one unauthenticated data route. The sandboxed widget can't read the
  token, so it returns only counts and the latest alert headline.

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

### `pynids xray` — Live "what is my browser hiding from me?"

The DevTools "Network" tab is a curated view: it shows the renderer's
own `fetch`/`XHR` calls and very little else. **X-Ray mode** reveals
everything the browser does behind that view — in a single live
terminal dashboard.

```bash
sudo pynids xray --iface en0
```

Surfaces, in real time:

| Panel | What it shows |
|---|---|
| **WebRTC / IP leaks** | STUN/TURN exchanges + leaked private/loopback IPs (the classic "WebRTC IP leak" that bypasses VPN tunnels) |
| **Localhost / private probes** | Connections to `127.0.0.0/8` and RFC1918 ranges — the fingerprinting trick where webpages port-scan your machine |
| **QUIC / HTTP-3 endpoints** | Every QUIC Initial packet — every HTTP/3 connection starts here and is invisible in DevTools |
| **WebSocket sessions** | Bi-directional channels initiated by `Upgrade: websocket` |
| **Trackers · Beacons · Prefetch** | Known third-party trackers (Google Analytics, Meta Pixel, DoubleClick, Hotjar, …), `navigator.sendBeacon` POSTs, 1×1 tracking pixels, and DNS prefetch storms |
| **Live event stream** | Rolling chronological log of every hidden event |

Common invocations:

```bash
# Watch a single interface (most common)
sudo pynids xray --iface en0

# Persist a JSON line per event in addition to the live dashboard
sudo pynids xray --iface en0 --json-log xray.jsonl

# Replay a PCAP through the X-Ray pipeline
pynids xray --iface en0 --pcap capture.pcapng --no-localhost

# Linux: the loopback interface is `lo`, not `lo0`
sudo pynids xray --iface eth0 --loopback-iface lo
```

> **Note:** `--also-localhost` (default on) launches a second sniffer
> on the loopback device so the dashboard can detect browser-initiated
> connections to `127.0.0.1`, which never leave the host's main NIC.

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

### `pynids stats` — Alert statistics from SQLite

```bash
pynids stats --db alerts.db
pynids stats --db alerts.db --json
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
layer7.dns.name_entropy      layer7.dns.answers
layer7.tls.sni               layer7.tls.alpn
layer7.tls.ja3               layer7.tls.ech
layer7.quic.sni              layer7.quic.alpn
layer7.ssh.software
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

**Live feeds** (recommended) are downloaded by `pynids intel update` and refreshed by the
daemon every 6 hours. They're cached in the data directory and checked against every IP, DNS
name, and TLS/QUIC SNI:

| Feed | Source | Used for |
|---|---|---|
| `feodo` | abuse.ch Feodo Tracker | botnet C2 IPs (CRITICAL) |
| `spamhaus_drop_v4` / `_v6` | Spamhaus DROP | hijacked / criminal netblocks (HIGH) |
| `tor_exits` | Tor Project | Tor exit relays (LOW) |
| `urlhaus` | abuse.ch URLhaus | malware-distribution hosts (HIGH) |
| `disconnect` | Disconnect.me | 4,000+ tracker domains |
| `doh_domains` / `doh_ipv4` | dibdot DoH lists | encrypted-DNS resolvers |

`pynids intel status` shows what's cached. The YAML files below add your own indicators on top.

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

### Stealth / X-Ray rule IDs

X-Ray detectors emit `behavioral` alerts whose `rule_id` starts with
`STEALTH-…`, so they sit naturally alongside the rest of the alert
ecosystem and can be queried, persisted, and correlated like any other
alert.

| Rule ID | What triggered it |
|---|---|
| `STEALTH-WEBRTC-LEAK` | STUN response leaked a private/loopback IP (HIGH) |
| `STEALTH-WEBRTC-REFLEXIVE` | STUN response leaked a public reflexive address (LOW) |
| `STEALTH-WEBRTC-STUN` / `STEALTH-WEBRTC-TURN` | STUN/TURN binding/allocate request (LOW) |
| `STEALTH-LOCALHOST-PROBE` | TCP/UDP packet to `127.0.0.0/8` or RFC1918 on an unusual port |
| `STEALTH-LOCALHOST-SCAN` | Same source probed N+ ports on a private/loopback host (CRITICAL) |
| `STEALTH-QUIC-INITIAL` | First QUIC Initial packet to a destination (HTTP/3) |
| `STEALTH-WEBSOCKET` | HTTP `Upgrade: websocket` handshake |
| `STEALTH-BEACON` | `navigator.sendBeacon` POST or 1×1 tracking pixel |
| `STEALTH-DNS-PREFETCH` | Burst of unique third-party DNS lookups (`<link rel="dns-prefetch">`) |
| `STEALTH-TRACKER` | Connection to a known analytics/tracker domain (TLS/QUIC SNI, HTTP Host, or DNS) |
| `STEALTH-ENCRYPTED-DNS` | DNS-over-HTTPS / TLS / QUIC session: lookups that bypass the system resolver |

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
| [psutil](https://github.com/giampaolo/psutil) | ≥ 5.9.0 | Per-connection app attribution |
| [cryptography](https://cryptography.io/) | ≥ 41.0.0 | QUIC Initial decryption |
| [maxminddb](https://github.com/maxmind/MaxMind-DB-Reader-python) | ≥ 2.4.0 | GeoIP / ASN (`[geo]` extra) |
| [anthropic](https://github.com/anthropics/anthropic-sdk-python) | ≥ 0.75.0 | Explain with Claude (`[ai]` extra) |

**Dev only:** `pytest>=7.4`, `pytest-cov>=4.1`. **Menu bar app:** Xcode Command Line Tools (`xcode-select --install`).

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0). Tracker list by
[Disconnect](https://disconnect.me/trackerprotection) (CC BY-NC-SA 4.0).

---

## 📄 License

This project is distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 📚 Further Reading

- [`documentation.md`](documentation.md) — Deep technical reference covering every module, data flow, design decisions, and internal APIs.
- [MITRE ATT&CK](https://attack.mitre.org/) — Framework referenced by all detection rules and alerts.
- [Scapy documentation](https://scapy.readthedocs.io/) — Underlying packet capture library.
