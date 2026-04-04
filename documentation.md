# PyNIDS — Deep Technical Documentation

> **Version:** 1.0.0 · **License:** MIT · **Python:** ≥ 3.9

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture at a Glance](#2-architecture-at-a-glance)
3. [Directory Structure](#3-directory-structure)
4. [Packet Capture Layer — `sniffer.py`](#4-packet-capture-layer--snifferpy)
5. [Protocol Dissector — `protocols/dissector.py`](#5-protocol-dissector--protocolsdissectorpy)
6. [Flow Tracker — `flow/tracker.py`](#6-flow-tracker--flowtrackerpy)
7. [Detection Engine — `engine.py`](#7-detection-engine--enginepy)
8. [Detection Subsystems](#8-detection-subsystems)
   - 8.1 [Signature Detection](#81-signature-detection)
   - 8.2 [Anomaly Detection](#82-anomaly-detection)
   - 8.3 [Behavioral Detection](#83-behavioral-detection)
9. [Threat Intelligence — `intel/threat_intel.py`](#9-threat-intelligence--intelthreat_intelpy)
10. [Alert System](#10-alert-system)
    - 10.1 [Alert Model](#101-alert-model)
    - 10.2 [Alert Manager](#102-alert-manager)
    - 10.3 [Output Backends](#103-output-backends)
11. [CLI — `cli.py`](#11-cli--clipy)
12. [Configuration Reference](#12-configuration-reference)
13. [Rule Language Reference](#13-rule-language-reference)
14. [Data Flow — End-to-End Packet Journey](#14-data-flow--end-to-end-packet-journey)
15. [Test Suite](#15-test-suite)
16. [Design Decisions & Trade-offs](#16-design-decisions--trade-offs)

---

## 1. Project Overview

PyNIDS is an **enterprise-grade, pure-Python Network Intrusion Detection System** built on top of [Scapy](https://scapy.net/). It monitors network traffic either from a live interface or a pre-recorded PCAP file, and raises structured security alerts by running every packet through a multi-layer detection pipeline.

### Core capabilities

| Capability | Implementation |
|---|---|
| Live packet capture | Scapy `AsyncSniffer` + bounded thread-safe queue |
| PCAP/PCAPNG replay | Scapy `PcapReader` |
| Protocol dissection | Pure-Python HTTP/DNS/TLS/SSH/SMTP parsers |
| Stateful flow tracking | In-memory 5-tuple connection table with TCP state machine |
| Signature detection | Declarative YAML rule language with threshold gating |
| Statistical anomaly detection | EWMA volumetric spikes, port-scan, brute-force |
| Behavioral detection | DNS tunneling, HTTP attacks, data exfiltration, C2 beaconing |
| Threat intelligence | CIDR/domain IOC feeds (YAML), checked every packet |
| Alert management | Deduplication, suppression allowlists, multi-vector correlation |
| Output backends | Console (Rich), JSON (rotating file), SQLite, Syslog |
| Hot-reload | Rules can be swapped atomically at runtime without stopping the engine |
| CLI | Click + Rich, five commands: `live`, `pcap`, `query`, `stats`, `validate` |

---

## 2. Architecture at a Glance

```
Network Interface / PCAP File
          │
          ▼
  ┌───────────────────┐
  │   Sniffer Layer   │   sniffer.py
  │  (AsyncSniffer /  │   • Captures raw packets
  │   PcapReader)     │   • Normalises into meta dict
  └────────┬──────────┘
           │ meta dict (src_ip, dst_ip, protocol, payload_bytes, …)
           ▼
  ┌───────────────────────────────────────────────────────┐
  │                  DetectionEngine                       │  engine.py
  │                                                       │
  │  1. dissect(meta)    ──► Protocol Dissector           │
  │  2. flow_tracker.update(meta) ──► Flow Table          │
  │  3. _run_threat_intel(meta, layer7)                   │
  │  4. for detector in [Signature, Anomaly×3,            │
  │                       Behavioral×4]:                  │
  │        detector.analyze(meta, layer7, flow)           │
  └────────┬──────────────────────────────────────────────┘
           │ List[Alert]
           ▼
  ┌───────────────────┐
  │   AlertManager    │   alerts/manager.py
  │  • Dedup          │
  │  • Suppress       │
  │  • Correlate      │
  └────────┬──────────┘
           │
     ┌─────┼──────────┬───────────┐
     ▼     ▼          ▼           ▼
  Console  JSON    SQLite      Syslog
  (Rich)   file    database    server
```

The engine is **single-threaded and synchronous** by design — predictable, testable, and debuggable. The only concurrency is in the sniffer layer itself: Scapy's `AsyncSniffer` runs in a background thread and hands packets to the engine via a bounded `queue.Queue`, preventing the capture callback from blocking the sniffer thread.

---

## 3. Directory Structure

```
PyNIDS/
├── pyproject.toml                  # Build config, dependencies, CLI entry point
├── configs/
│   ├── default.yaml                # Minimal fallback config
│   └── enterprise.yaml             # Full config with all tuneable parameters
├── rules/
│   ├── sample_rules.yaml           # Minimal rule example
│   └── enterprise_rules.yaml       # 20+ production-ready signature rules
├── intel/
│   ├── known_bad_ips.yaml          # CIDR-based bad IP feed
│   └── malicious_domains.yaml      # Domain/suffix blocklist feed
├── tests/
│   ├── conftest.py                 # Shared fixtures (engine, mock packets, …)
│   ├── test_alert_manager.py
│   ├── test_anomaly.py
│   ├── test_behavioral.py
│   ├── test_engine.py
│   ├── test_flow.py
│   ├── test_protocols.py
│   ├── test_rules.py
│   └── test_signature.py
└── pynids/                         # The installable package
    ├── __init__.py                 # Version, quick-start docstring
    ├── cli.py                      # Click CLI (live, pcap, query, validate)
    ├── config.py                   # YAML config loader + defaults merger
    ├── detectors.py                # Convenience re-exports
    ├── engine.py                   # DetectionEngine orchestrator
    ├── rules.py                    # Rule loader shim
    ├── sniffer.py                  # Packet capture + meta normalisation
    ├── alerts/
    │   ├── model.py                # Alert dataclass, Severity, AlertType enums
    │   ├── manager.py              # AlertManager (dedup/suppress/correlate/dispatch)
    │   └── outputs/
    │       ├── console.py          # Rich-formatted terminal output
    │       ├── json_file.py        # Rotating JSON-lines file
    │       ├── sqlite_out.py       # SQLite persistence + query API
    │       └── syslog_out.py       # UDP/TCP syslog forwarding
    ├── detection/
    │   ├── base.py                 # BaseDetector abstract class
    │   ├── signature.py            # YAML rule engine
    │   ├── anomaly.py              # EWMA, PortScan, BruteForce detectors
    │   └── behavioral.py          # DNS tunneling, HTTP attacks, Exfil, Beaconing
    ├── flow/
    │   └── tracker.py              # FlowTracker + Flow dataclass
    ├── intel/
    │   └── threat_intel.py         # ThreatIntel IOC loader & lookup
    └── protocols/
        └── dissector.py            # HTTP, DNS, TLS, SSH, SMTP parsers
```

---

## 4. Packet Capture Layer — `sniffer.py`

### 4.1 `packet_to_meta(pkt) → dict`

Converts a raw Scapy packet into a **normalised metadata dictionary** that all downstream components consume. This is the only place where Scapy's object model is touched; everywhere else in PyNIDS, a plain Python dict is passed around.

| Key | Type | Description |
|---|---|---|
| `timestamp` | `float` | Unix epoch of capture time |
| `protocol` | `str` | `'tcp'`, `'udp'`, `'icmp'`, `'icmpv6'`, `'other'` |
| `src_ip` | `str` | Source IP (v4 or v6 string) |
| `dst_ip` | `str` | Destination IP |
| `src_port` | `int \| None` | Source TCP/UDP port (None for ICMP) |
| `dst_port` | `int \| None` | Destination TCP/UDP port |
| `tcp_flags` | `int` | Bitmask of TCP flags (0 for non-TCP) |
| `payload_bytes` | `bytes` | Application-layer payload (may be empty) |
| `ip_ttl` | `int \| None` | IP TTL / Hop Limit |
| `ip_tos` | `int \| None` | IP ToS / DSCP byte |
| `packet_len` | `int` | Total captured packet length in bytes |

The function is intentionally **non-throwing**: non-IP packets (ARP, pure Ethernet) return a dict with most fields set to `None`. The engine handles `None` gracefully throughout.

### 4.2 `sniff_live(iface, engine_callback, bpf_filter, packet_queue_size)`

```
AsyncSniffer thread               Main thread
──────────────────────────────────────────────────────────
for each raw packet                while True:
  meta = packet_to_meta(pkt)         meta = queue.get(timeout=0.2)
  queue.put_nowait(meta) ──────────► engine_callback(meta)
  (drops silently if queue full)
```

- The sniffer runs in a **dedicated background thread** (`AsyncSniffer`). Its only job is to call `packet_to_meta` and push the result into a bounded (`maxsize=10 000`) `queue.Queue`.
- The main thread drains packets with a 0.2 s timeout so that `KeyboardInterrupt` is still responsive.
- **Back-pressure**: if the engine cannot keep up, packets are silently dropped (with a warning logged every 1000th drop). This prevents memory exhaustion under burst traffic.
- On `KeyboardInterrupt` the sniffer is stopped cleanly and the final drop count is logged.

Requires **root/administrator privileges** (raw socket access).

### 4.3 `replay_pcap(pcap_path, engine_callback) → int`

Reads packets sequentially from a PCAP or PCAPNG file via Scapy's `PcapReader`. No threading, no queue — purely sequential. Returns the total packets processed.

**Use case:** offline forensics, CI/CD testing, benchmarking the detection pipeline without a network interface.

---

## 5. Protocol Dissector — `protocols/dissector.py`

### 5.1 `dissect(meta) → dict` (the `layer7` dict)

The dissector's job is to produce a **supplementary `layer7` dict** for each packet, containing parsed application-layer fields. It uses the destination and source ports to infer the application protocol and then delegates to a protocol-specific parser.

Port routing table:
| Ports | Protocol | Parser |
|---|---|---|
| 53 (src or dst) | DNS | `_parse_dns` |
| 80, 8080, 8000, 8008 | HTTP | `_parse_http` |
| 443, 8443 | TLS | `_parse_tls_client_hello` |
| 22 | SSH | `_parse_ssh_banner` |
| 25, 465, 587 | SMTP | `_parse_smtp` |

The `layer7` dict is keyed by `app_proto` plus a protocol-specific nested dict. All parsers are purely defensive (wrapped in `try/except`) — a malformed packet that causes a parser exception simply returns an empty dict, and detection continues.

### 5.2 HTTP Parser (`_parse_http`)

Decodes the payload as UTF-8 (with error replacement), extracts:
- **Request line**: method, URI, HTTP version
- **Response line**: status code, reason
- **Headers**: host, user-agent, content-type, content-length, referer
- **Security heuristics** (boolean flags used by `HttpAttackDetector` and signature rules):

| Flag | Regex Pattern | Description |
|---|---|---|
| `sqli_suspect` | `union select`, `drop table`, `1=1`, `sleep(`, `benchmark(`, etc. | SQL injection signatures |
| `xss_suspect` | `<script`, `javascript:`, `onerror=`, `document.cookie`, `fromCharCode` | XSS payloads |
| `path_traversal_suspect` | `../`, `..\`, `%2e%2e` | Directory traversal attempts |
| `scanner_ua` | nikto, sqlmap, nmap, masscan, burpsuite, nuclei, nessus, …  | Known scanner user-agents |

### 5.3 DNS Parser (`_parse_dns`)

Manually decodes the binary DNS wire format:
- Transaction ID, QR flag, opcode, RCODE, answer count
- Question section: query name (with pointer decompression), query type
- **Tunneling metadata** for `DnsTunnelingDetector`:
  - `name_entropy`: Shannon entropy (bits/byte) of the lowercased query name
  - `name_length`: total character length of the domain name
  - `subdomain_depth`: count of `.` separators (label depth)

DNS pointer recursion is guarded with a `visited` set to prevent infinite loops on malformed packets.

### 5.4 TLS ClientHello Parser + JA3 (`_parse_tls_client_hello`)

Parses the binary TLS record for `ClientHello` (handshake type `0x01`):
- TLS version advertised by the client
- **SNI** (Server Name Indication) extracted from extension type `0x0000`
- Cipher suite list (GREASE values `0xXAXA` excluded)
- Extensions list, elliptic curves, EC point formats

**JA3 fingerprint** computation:
```
ja3_str = f"{client_version},{ciphers_dash_sep},{extensions_dash_sep},{curves},{ec_formats}"
ja3 = md5(ja3_str)
```

JA3 hashes can be matched in signature rules against known malware client fingerprints (e.g., Cobalt Strike, Metasploit).

### 5.5 SSH Banner Parser (`_parse_ssh_banner`)

Extracts software name and protocol version from the SSH banner line:
```
SSH-{proto_version}-{software} {comments}
```
Useful for detecting old or vulnerable SSH software versions via signature rules.

### 5.6 SMTP Parser (`_parse_smtp`)

Extracts: `EHLO`/`HELO` hostname, `MAIL FROM`, `RCPT TO`, and `AUTH` mechanism from SMTP command streams. Supports phishing/spam detection and unusual mail routing via signature rules.

---

## 6. Flow Tracker — `flow/tracker.py`

### 6.1 Flow Identification

The `FlowTracker` maintains an in-memory **connection table** (`dict[flow_id → Flow]`). The flow ID is a canonical MD5 hash of the 5-tuple `(proto, lower_endpoint, higher_endpoint)` — endpoints are sorted so that A→B and B→A map to the **same flow entry** (bidirectional tracking).

```python
ep1 = (src_ip, src_port)
ep2 = (dst_ip, dst_port)
low, high = sorted([ep1, ep2])
raw = f"{proto}:{low[0]}:{low[1]}:{high[0]}:{high[1]}"
flow_id = md5(raw)
```

### 6.2 `Flow` Dataclass

| Field | Description |
|---|---|
| `flow_id` | MD5 of canonical 5-tuple |
| `protocol` | `'tcp'`, `'udp'`, `'icmp'` |
| `src_ip / src_port` | Initiating endpoint (first packet direction) |
| `dst_ip / dst_port` | Responding endpoint |
| `state` | `NEW → ESTABLISHED → CLOSING → CLOSED` |
| `start_time / last_seen` | First/last packet timestamps |
| `packet_count` | Cumulative packet count (both directions) |
| `byte_count` | Cumulative payload bytes |
| `tcp_flags_seen` | Bitmask union of all TCP flags seen in this flow |

Computed properties:
- `duration`: `last_seen - start_time`
- `avg_packet_size`: `byte_count / packet_count`

### 6.3 TCP State Machine

The tracker advances a simple state machine per flow based on TCP flag bitmasks:

```
NEW (SYN seen, no ACK) → ESTABLISHED (ACK seen after NEW) → CLOSING (FIN or RST seen)
```

### 6.4 Memory Management

The tracker runs garbage collection every 30 seconds (lazy, event-driven):
1. All flows idle beyond `idle_timeout` seconds are deleted.
2. If the table still exceeds `max_flows`, the **oldest** flows (by `last_seen`) are evicted until the table is within capacity.

Default limits: `max_flows=100 000`, `idle_timeout=300 s`.

---

## 7. Detection Engine — `engine.py`

`DetectionEngine` is the **central orchestrator** that wires the capture layer to all detection subsystems. It exposes a single public method `process_packet(meta)` that constitutes the entire detection pipeline.

### 7.1 Initialisation

On construction the engine:
1. Reads `config` dict (from `configs/*.yaml`) to configure all subsystems.
2. Creates a `FlowTracker`.
3. (Optionally) loads `ThreatIntel` feeds.
4. Creates an `AlertManager` with the configured dedup / suppression / correlation settings.
5. Instantiates **all detectors in order** (cheapest / most likely to fire first):
   - `SignatureDetector` — loaded from the rules YAML
   - `AnomalyDetector` — EWMA volumetric
   - `PortScanDetector` — horizontal & vertical
   - `BruteForceDetector` — credential-service attack detection
   - `DnsTunnelingDetector`
   - `HttpAttackDetector`
   - `DataExfiltrationDetector`
   - `BeaconingDetector`

### 7.2 `process_packet(meta) → List[Alert]`

```python
with self._lock:                      # Thread-safe packet counter
    self._packets_processed += 1
    layer7 = dissect(meta)            # Step 1: enrich meta with L7 fields
    flow = self._flow_tracker.update(meta)  # Step 2: update flow table
    ti_alerts = self._run_threat_intel(meta, layer7)  # Step 3: IOC check
    for detector in self._detectors:
        for alert in detector.analyze(meta, layer7, flow):  # Step 4
            alerts.append(alert)

for alert in alerts:
    self._alert_manager.add(alert)    # Step 5: dedup/suppress/dispatch
return alerts
```

The lock covers steps 1–4 to ensure each packet is fully processed before the statistics counter advances. Step 5 (alert dispatch) happens outside the lock so slow output backends cannot cascade delays back into the packet processing path.

### 7.3 Hot-Reload (`reload_rules()`)

`reload_rules()` checks the modification time of the rules file. If the mtime has changed since the last load it:
1. Calls `load_rules()` to parse the new YAML.
2. Acquires the engine lock.
3. Calls `SignatureDetector.update_rules(new_rules)`, which atomically replaces the rule list and clears threshold tracking state.

No packets are ever evaluated against a partially loaded ruleset.

### 7.4 `stats` Property

```python
{
    "uptime_seconds": float,
    "packets_processed": int,
    "packets_per_second": float,
    "active_flows": int,
    "alert_stats": {
        "total_seen": int,
        "total_suppressed": int,
        "total_deduplicated": int,
        "total_emitted": int,
    }
}
```

---

## 8. Detection Subsystems

All detectors extend `BaseDetector` and implement a single method:

```python
def analyze(self, meta: dict, layer7: dict, flow: Optional[Flow]) -> Iterable[Alert]:
    ...
```

### 8.1 Signature Detection

**File:** `detection/signature.py`  
**Class:** `SignatureDetector`

#### Rule Evaluation

For each packet, every rule in the loaded set is evaluated:

1. The rule's `match` tree is recursively evaluated via `_eval_node`.
2. If the match fails → no alert.
3. If a `threshold` block is present → check that this rule has matched at least `count` times from this `src_ip` within `seconds`. If not → no alert yet.
4. If threshold is met → emit an `Alert` of type `SIGNATURE`.

#### Condition Evaluator (`_eval_node`)

Supports three node types:

| Node Type | Syntax | Semantics |
|---|---|---|
| AND combinator | `all: [node, node, …]` | All children must match |
| OR combinator | `any: [node, node, …]` | At least one child must match |
| NOT combinator | `not: node` | Inverts the child |
| Leaf condition | `{field: X, op: OP, value: V}` | Apply operator |
| Shorthand | `{key: value, key2: value2}` | Implicit AND of equality checks |

#### Field Addressing

- Plain names (`src_ip`, `dst_port`, `protocol`, `payload_bytes`) → resolved from `meta` dict.
- Dot notation starting with `layer7.` → resolved from the `layer7` dict. Example: `layer7.http.user_agent`, `layer7.dns.query_name`, `layer7.tls.sni`, `layer7.tls.ja3`.

#### Operator Reference

| Operator | Type check | Semantics |
|---|---|---|
| `eq` | any | Exact equality |
| `ne` | any | Not equal |
| `lt / gt` | numeric | Less/greater than |
| `lte / gte` | numeric | Less/greater than or equal |
| `in` | any | Value is in list |
| `not_in` | any | Value is not in list |
| `contains` | str or bytes | Substring (bytes-aware) |
| `startswith` | str | String prefix match |
| `regex` | str | `re.search`, case-insensitive |
| `exists` | any | Field is present and not None |

#### Threshold Gating

```yaml
threshold:
  count: 5      # Must match N times …
  seconds: 30   # … within this sliding window
```

Per `(rule_id, src_ip)` pair, a `deque[float]` of match timestamps is maintained. Old entries are expired on each check. The alert fires only when `len(bucket) >= count`. This enables rate-sensitive rules (e.g., "alert if SYN to port 22 is seen 5 times in 30 seconds from the same IP") without generating alert storms.

### 8.2 Anomaly Detection

**File:** `detection/anomaly.py`

#### `AnomalyDetector` — EWMA Volumetric Spike Detection

Maintains per-source-IP state:
- A **sliding window** of per-`window_seconds` packet counts (deque, maxlen=60 windows)
- An **Exponentially Weighted Moving Average** (EWMA) of packet rates

On each packet from `src_ip`:
1. Increment the count for the current time window.
2. Update EWMA: `rate_ewma = α * current_rate + (1-α) * rate_ewma`
3. Compute the sample **standard deviation** over all stored window rates.
4. Alert if `current_rate > ewma + σ * stddev` AND `current_count > 5` (minimum volume guard).

**MITRE:** `T1498` (Endpoint Denial of Service)

**Key parameters (enterprise.yaml):**
| Parameter | Default | Effect |
|---|---|---|
| `ewma_alpha` | 0.3 | Smoothing: higher → adapts faster to new baseline |
| `sigma_threshold` | 3.5 | How many std devs above mean = anomalous |
| `window_seconds` | 10 | Counting slice width |

#### `PortScanDetector` — Horizontal & Vertical Scan

Maintains per-source-IP `_ScanState`:

**Horizontal scan (host sweep):** one source probes the **same port** across many destination IPs.
- Track `{dst_port → set of dst_ips}` with a first-seen timestamp per port.
- Alert when `len(dst_ips) >= horizontal_threshold` within `horizontal_window` seconds.
- **MITRE:** `T1046`

**Vertical scan (port scan):** one source probes **many ports** on the same destination.
- Track `{dst_ip → set of dst_ports}` with a first-seen timestamp per target.
- Alert when `len(dst_ports) >= vertical_threshold` within `vertical_window` seconds.
- **MITRE:** `T1046`

Per-port and per-target alert suppression (`horiz_alerted` / `vert_alerted` sets) prevents alert storms within a window.

**Key parameters (enterprise.yaml):**
| Parameter | Default |
|---|---|
| `horizontal_threshold` | 15 unique dst IPs |
| `horizontal_window` | 60 s |
| `vertical_threshold` | 12 unique dst ports |
| `vertical_window` | 60 s |

#### `BruteForceDetector` — Credential Service Attack

Monitors connection attempts to authentication services. Maintains a `deque[float]` of timestamps per `(src_ip, dst_ip, dst_port)` key.

Alert condition: `len(bucket_within_window) >= threshold`

**Default watched ports:** 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 110 (POP3), 143 (IMAP), 389 (LDAP), 636 (LDAPS), 3389 (RDP), 5900 (VNC), 8080 (HTTP alt).

**MITRE:** `T1110`

### 8.3 Behavioral Detection

**File:** `detection/behavioral.py`

#### `DnsTunnelingDetector` — Covert Channel via DNS

DNS tunneling tools (iodine, dnscat2) encode binary data as base62/hex in subdomain labels, producing extremely long and high-entropy domain names.

Alert fires when **any** of:
- `name_entropy >= entropy_threshold` (default 3.5 bits)
- `name_length >= length_threshold` (default 50 chars)
- `subdomain_depth >= depth_threshold` (default 5 labels)

Confidence is proportional to how far each metric exceeds its threshold.

**MITRE:** `T1071.004`

#### `HttpAttackDetector` — Web Application Attacks

Reads the boolean heuristic flags precomputed by `_parse_http` and maps them to severity-graded alerts:

| Heuristic | Severity | MITRE |
|---|---|---|
| `sqli_suspect` | CRITICAL | T1190 |
| `xss_suspect` | HIGH | T1059.007 |
| `path_traversal_suspect` | HIGH | T1083 |
| `scanner_ua` | LOW | T1595 |

#### `DataExfiltrationDetector` — Large Outbound Flows

Watches `flow.byte_count` on each packet. When a single flow exceeds `threshold_bytes` (default 10 MiB), a HIGH-severity alert is raised with the flow's full byte/packet statistics.

Each flow ID is tracked in `_alerted_flows` so the alert fires at most once per flow.

**MITRE:** `T1041`

#### `BeaconingDetector` — C2 Periodic Check-in

Maintains a deque (max 30 entries) of connection timestamps per `(src_ip, dst_ip, dst_port)` tuple. Once at least `min_connections` (default 6) samples are collected:

1. Compute **inter-arrival intervals** between consecutive timestamps.
2. Compute the **coefficient of variation**: `CV = stddev / mean`
3. A CV < `cv_threshold` (default 0.20) → the traffic is highly regular → beaconing suspected.

Low CV = very consistent timing = machine, not human.

Confidence: `max(0, 1.0 - cv / cv_threshold)` — a CV of 0 gives confidence 1.0.

**MITRE:** `T1071`

---

## 9. Threat Intelligence — `intel/threat_intel.py`

### Feed Format

**`intel/known_bad_ips.yaml`:**
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

**`intel/malicious_domains.yaml`:**
```yaml
entries:
  - domain: "malware-c2.example"
    category: c2
    severity: HIGH
    description: "Active C2 domain"
  - domain: ".dyndns.org"        # leading dot = suffix match
    category: dyndns
    severity: MEDIUM
    description: "Dynamic DNS often used for C2"
```

### Lookup Behaviour

- **IP lookup (`check_ip`):** `ipaddress.ip_address(ip) in network` — supports both exact `host/32` and CIDR range matching. First-match wins.
- **Domain lookup (`check_domain`):** case-folded, trailing dot stripped. Entries starting with `.` match any subdomain (suffix patterns). For example, `.dyndns.org` matches `www.evil.dyndns.org`.

The engine calls both `check_ip(src_ip)` and `check_ip(dst_ip)`, plus `check_domain(dns.query_name)` on every dissected DNS packet.

Each match generates a `THREAT_INTEL` alert at the severity specified in the feed, carrying `matched_indicator` and `category` in the evidence.

---

## 10. Alert System

### 10.1 Alert Model

**File:** `alerts/model.py`

Every detection result is an `Alert` dataclass with these fields:

| Field | Type | Description |
|---|---|---|
| `alert_id` | `str` | UUID4, unique per alert instance |
| `timestamp` | `float` | Unix epoch of alert creation |
| `alert_type` | `AlertType` | `SIGNATURE`, `ANOMALY`, `BEHAVIORAL`, `THREAT_INTEL`, `CORRELATION` |
| `severity` | `Severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `message` | `str` | Human-readable description |
| `src_ip / dst_ip` | `str?` | Endpoint addresses |
| `src_port / dst_port` | `int?` | Endpoint ports |
| `protocol` | `str?` | Transport protocol |
| `rule_id` | `str?` | Matched rule ID (signature alerts) |
| `flow_id` | `str?` | Flow's MD5 key |
| `confidence` | `float` | 0.0 (speculative) → 1.0 (certain) |
| `tags` | `List[str]` | Taxonomy tags, e.g. `['recon', 'portscan']` |
| `mitre_technique` | `str?` | MITRE ATT&CK technique ID, e.g. `T1046` |
| `evidence` | `dict` | Arbitrary key/value payload for analysis |

`Severity` supports comparison operators (`>=`, `<=`, etc.) using an ordinal `numeric` property.

`Alert.dedup_key` → `f"{rule_id or alert_type}|{src_ip}|{dst_ip}|{dst_port}"` — used for deduplication.

### 10.2 Alert Manager

**File:** `alerts/manager.py`

The `AlertManager` is the last gate before output. Every alert produced by the detection engine flows through these stages:

#### Stage 1: Severity Gate
Drop the alert if `alert.severity < min_severity`.

#### Stage 2: Suppression Allowlist
`_SuppressionEntry` checks `(rule_id, src_cidr)` pairs. `rule_id = "*"` suppresses all alerts from that CIDR.

#### Stage 3: Deduplication
```python
if dedup_key in self._dedup:
    last_ts, count = self._dedup[dedup_key]
    if (now - last_ts) < dedup_window:
        self.total_deduplicated += 1
        return False  # Suppress duplicate
```
Identical alerts (same rule, same src, same dst, same port) within `dedup_window` seconds (default 60 s) are collapsed. The `count` is tracked but the duplicate is not forwarded to outputs.

#### Stage 4: Dispatch
Calls `output.emit(alert)` on every registered `BaseOutput`. Exceptions in one output do not affect others.

#### Stage 5: Correlation
After dispatch, the alert's `(src_ip, rule_id/alert_type)` is recorded in a sliding window. If `>= correlation_threshold` **distinct** rule signatures are seen from the same source in `correlation_window` seconds, a `CORRELATION` alert (severity CRITICAL) is generated and dispatched immediately. This is the system's multi-vector attack detection.

### 10.3 Output Backends

All backends extend `BaseOutput` and must implement `emit(alert)`. They are registered with `alert_manager.register_output(backend)`.

| Backend | File | Description |
|---|---|---|
| `ConsoleOutput` | `outputs/console.py` | Rich-formatted, color-coded terminal output. Severity color map: CRITICAL=red bold, HIGH=red, MEDIUM=yellow, LOW=cyan. Optional evidence display. |
| `JsonFileOutput` | `outputs/json_file.py` | Appends `alert.to_dict()` as a JSON line. Rotates at `max_bytes` with `backup_count` archives. |
| `SQLiteOutput` | `outputs/sqlite_out.py` | Stores alerts in a `pynids_alerts` table. Provides a `query()` method for the `pynids query` CLI command. |
| `SyslogOutput` | `outputs/syslog_out.py` | Forwards alerts to a remote syslog server over UDP or TCP. RFC-5424 compatible. |

---

## 11. CLI — `cli.py`

Built with [Click](https://click.palletsprojects.com/) and [Rich](https://github.com/Textualize/rich). Entry point: `pynids` (defined in `pyproject.toml`).

### `pynids live`
```
pynids live --iface en0 --rules rules/enterprise_rules.yaml \
            [--bpf "not port 22"] [--config configs/enterprise.yaml] \
            [--sqlite alerts.db] [--output text|json] \
            [--min-severity LOW|MEDIUM|HIGH|CRITICAL] [--verbose]
```
Captures live traffic. Blocks until Ctrl-C. Prints session stats on exit.

### `pynids pcap`
```
pynids pcap --file capture.pcap --rules rules/enterprise_rules.yaml \
            [--sqlite alerts.db] [--output json]
```
Replays and analyses a PCAP file. Prints packet throughput and stats on completion.

### `pynids query`
```
pynids query --db alerts.db [--min-severity HIGH] \
             [--src-ip 10.0.0.5] [--type signature] [--limit 50] [--json]
```
Queries the SQLite alert database. Renders a Rich table or JSON lines.

### `pynids validate`
```
pynids validate rules/enterprise_rules.yaml
pynids validate configs/enterprise.yaml --type config
```
Validates a rules or config YAML file, printing a per-rule error summary.

### `pynids --version`
Prints the installed version and exits.

---

## 12. Configuration Reference

**File:** `configs/enterprise.yaml` (all keys shown with defaults)

```yaml
anomaly:
  ewma_alpha: 0.3          # EWMA smoothing factor (0–1)
  sigma_threshold: 3.5     # Std devs above mean → alert
  window_seconds: 10       # Counting window width

scan:
  horizontal_threshold: 15 # Unique dst IPs on same port
  horizontal_window: 60    # Window (seconds)
  vertical_threshold: 12   # Unique dst ports on same host
  vertical_window: 60

brute_force:
  threshold: 8             # Connection attempts before alert
  window: 30               # Sliding window (seconds)
  ports: [21, 22, 23, 25, 110, 143, 389, 636, 3389, 5900, 8080]

behavioral:
  dns_entropy_threshold: 3.5      # Shannon entropy ≥ → suspicious DNS
  dns_length_threshold: 50        # Query name chars ≥ → suspicious
  exfil_threshold_bytes: 10485760 # Flow bytes ≥ → exfil alert (10 MiB)
  beacon_min_connections: 6       # Sample size before beaconing analysis
  beacon_cv_threshold: 0.20       # CV ≤ → beaconing alert

flow:
  max_flows: 100000        # Max concurrent tracked flows
  idle_timeout: 300        # Inactivity seconds before flow expiry

intel:
  enabled: true
  bad_ips_file: intel/known_bad_ips.yaml
  malicious_domains_file: intel/malicious_domains.yaml

alert_manager:
  dedup_window: 60
  correlation_window: 120
  correlation_threshold: 3
  min_severity: LOW
  suppression: []
  # suppression:
  #   - rule_id: "SIG-LAT-001"
  #     src_cidr: "10.10.0.0/16"

outputs:
  console:
    enabled: true
    min_severity: LOW
    show_evidence: false
  json_file:
    enabled: false
    path: /var/log/pynids/alerts.json
    max_bytes: 10485760
    backup_count: 10
  sqlite:
    enabled: false
    path: /var/db/pynids/alerts.db
  syslog:
    enabled: false
    host: localhost
    port: 514
    protocol: udp
```

---

## 13. Rule Language Reference

Rules are defined in YAML under the top-level `rules:` key.

### Full Rule Schema

```yaml
rules:
  - id: "SIG-EXP-001"             # Required. Unique string identifier.
    description: "Human message"   # Alert message text.
    severity: HIGH                 # LOW | MEDIUM | HIGH | CRITICAL
    confidence: 0.9                # Float 0.0–1.0 (default 1.0)
    mitre: "T1190"                 # MITRE ATT&CK technique ID
    tags: [sqli, webapp]           # Free-form taxonomy tags
    match:                         # Required. Condition tree.
      all:
        - {field: protocol, op: eq, value: tcp}
        - {field: dst_port, op: in, value: [80, 8080]}
        - {field: layer7.http.sqli_suspect, op: eq, value: true}
    threshold:                     # Optional. Rate gate.
      count: 5
      seconds: 30
    action: alert                  # Reserved for future use (currently ignored).
```

### Addressable Fields

| Field Name | Source | Example Value |
|---|---|---|
| `src_ip` | meta | `"192.168.1.10"` |
| `dst_ip` | meta | `"10.0.0.1"` |
| `src_port` | meta | `54321` |
| `dst_port` | meta | `22` |
| `protocol` | meta | `"tcp"` |
| `tcp_flags` | meta | `18` (SYN+ACK) |
| `ip_ttl` | meta | `64` |
| `payload_bytes` | meta | `b"GET / HTTP/1.1\r\n..."` |
| `layer7.http.method` | layer7 | `"POST"` |
| `layer7.http.uri` | layer7 | `"/admin?id=1 OR 1=1"` |
| `layer7.http.user_agent` | layer7 | `"nikto/..."` |
| `layer7.http.sqli_suspect` | layer7 | `true` |
| `layer7.http.xss_suspect` | layer7 | `true` |
| `layer7.http.scanner_ua` | layer7 | `true` |
| `layer7.dns.query_name` | layer7 | `"evil.example.com"` |
| `layer7.dns.query_type` | layer7 | `"TXT"` |
| `layer7.dns.name_entropy` | layer7 | `4.2` |
| `layer7.tls.sni` | layer7 | `"malware-c2.example"` |
| `layer7.tls.ja3` | layer7 | `"abc123..."` |
| `layer7.ssh.software` | layer7 | `"OpenSSH_7.2"` |

---

## 14. Data Flow — End-to-End Packet Journey

```
1. NIC / PCAP  ──► packet_to_meta()
                       │
                       │  meta = {timestamp, src_ip, dst_ip, protocol,
                       │          src_port, dst_port, tcp_flags,
                       │          payload_bytes, ip_ttl, ip_tos, packet_len}
                       ▼
2.                 dissect(meta)
                       │
                       │  layer7 = {
                       │    app_proto: "http",
                       │    http: {uri, method, sqli_suspect: true, …}
                       │  }
                       ▼
3.             flow_tracker.update(meta)
                       │
                       │  flow = Flow(byte_count=14000, state=ESTABLISHED, …)
                       ▼
4a.            threat_intel.check_ip(src_ip)    → ThreatEntry | None
4b.            threat_intel.check_ip(dst_ip)    → ThreatEntry | None
4c.            threat_intel.check_domain(dns.query_name) → ThreatEntry | None
                       │  → [THREAT_INTEL Alert] if matched
                       ▼
5.             SignatureDetector.analyze(meta, layer7, flow)
                       │  → evaluates all 20+ rules; matches SIG-EXP-001
                       │  → [SIGNATURE Alert | severity=CRITICAL]
                       ▼
6.             AnomalyDetector.analyze(meta, …)
7.             PortScanDetector.analyze(meta, …)
8.             BruteForceDetector.analyze(meta, …)
9.             DnsTunnelingDetector.analyze(meta, layer7, …)
10.            HttpAttackDetector.analyze(meta, layer7, …)
11.            DataExfiltrationDetector.analyze(meta, …, flow)
12.            BeaconingDetector.analyze(meta, …)
                       │
                       │  alerts = [Alert(SIGNATURE, CRITICAL, …), …]
                       ▼
13.            AlertManager.add(alert) for each alert
                   A. Severity gate → pass
                   B. Suppression check → not suppressed
                   C. Dedup check → first occurrence, not duplicate
                   D. Dispatch to ConsoleOutput / JsonFileOutput / SQLiteOutput
                   E. Update correlation window → no correlation yet
                       │
                       ▼
14.            Terminal / JSON file / SQLite / Syslog
```

---

## 15. Test Suite

**Location:** `tests/`  
**Runner:** pytest (`pytest -v --tb=short`)

| Test File | Covers |
|---|---|
| `test_alert_manager.py` | Dedup, suppression (CIDR), correlation, severity gate |
| `test_anomaly.py` | EWMA spike detection, port-scan (h+v), brute-force |
| `test_behavioral.py` | DNS tunneling, HTTP attacks, data exfil, beaconing |
| `test_engine.py` | Full pipeline with mock packets, hot-reload |
| `test_flow.py` | Flow creation, TCP state machine, GC / max_flows eviction |
| `test_protocols.py` | HTTP/DNS/TLS/SSH/SMTP parsers with crafted payloads |
| `test_rules.py` | Rule loading from YAML |
| `test_signature.py` | Rule evaluation, operators, threshold gating, dot-notation fields |

**Fixtures (`conftest.py`):**
- `make_meta(**kwargs)` — factory for a minimal packet meta dict
- `make_engine()` — full `DetectionEngine` instance with enterprise config
- Various TCP/HTTP/DNS packet fixtures

**Coverage:** run with `pytest --cov=pynids --cov-report=term-missing`

---

## 16. Design Decisions & Trade-offs

| Decision | Rationale |
|---|---|
| **Single-threaded engine** | Simplifies all detector state management. No locking needed inside detectors. The capture queue decouples I/O from processing. |
| **Plain Python dicts for meta/layer7** | Zero-copy, easily serialised, testable without Scapy. Enables pure-Python unit tests. |
| **Pure-Python protocol parsers** | No dependency on Scapy's (expensive) deep-dissection in the hot path. Scapy is only used at the capture boundary. |
| **EWMA for anomaly detection** | Lightweight (O(1) per packet per source). Adapts to legitimate traffic growth without manual baseline tuning. |
| **CV-based beaconing** | Works regardless of the actual beacon interval (fast or slow). Low memory per tracked tuple. |
| **Canonical flow keys (sorted endpoints)** | Bidirectional tracking with no extra overhead — replies naturally update the same flow entry. |
| **Lazy GC on flow table** | Avoids a background thread. GC runs at most every 30 s, amortising its cost across many packets. |
| **YAML rule language** | Human-writable, diffable, auditable by non-developers. Hot-reloadable without code changes. |
| **Bounded capture queue** | Prevents unbounded memory growth under traffic bursts at the cost of dropping packets. |
| **Alert dedup keyed on (rule|type, src, dst, port)** | Suppresses alert storms from sustained attacks without losing the first occurrence. |
| **Correlation as a meta-alert** | Lets SIEM consumers treat multi-vector attacks as a single high-priority event. |
