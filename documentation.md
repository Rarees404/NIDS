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
   - 8.4 [Stealth / X-Ray Detection](#84-stealth--x-ray-detection)
9. [Threat Intelligence — `intel/threat_intel.py`](#9-threat-intelligence--intelthreat_intelpy)
10. [Alert System](#10-alert-system)
    - 10.1 [Alert Model](#101-alert-model)
    - 10.2 [Alert Manager](#102-alert-manager)
    - 10.3 [Output Backends](#103-output-backends)
    - 10.4 [X-Ray Live Dashboard](#104-x-ray-live-dashboard)
11. [CLI — `cli.py`](#11-cli--clipy)
12. [Configuration Reference](#12-configuration-reference)
13. [Rule Language Reference](#13-rule-language-reference)
14. [Data Flow — End-to-End Packet Journey](#14-data-flow--end-to-end-packet-journey)
15. [Test Suite](#15-test-suite)
16. [Design Decisions & Trade-offs](#16-design-decisions--trade-offs)
17. [Version 2: Always-On Service, Enrichment & Response](#17-version-2-always-on-service-enrichment--response)
18. [Host Inspection: Programs, Persistence, IP Dossiers, LAN, Claude Investigation](#18-host-inspection-programs-persistence-ip-dossiers-lan-claude-investigation)

---

## 1. Project Overview

PyNIDS is an **enterprise-grade, pure-Python Network Intrusion Detection System** built on top of [Scapy](https://scapy.net/). It monitors network traffic either from a live interface or a pre-recorded PCAP file, and raises structured security alerts by running every packet through a multi-layer detection pipeline.

### Core capabilities

| Capability | Implementation |
|---|---|
| Live packet capture | Scapy's BPF / `AF_PACKET` listen socket, raw frames decoded with `struct`, bounded thread-safe queue |
| PCAP/PCAPNG replay | Scapy `PcapReader` |
| Protocol dissection | Pure-Python HTTP/DNS/TLS/SSH/SMTP parsers |
| Stateful flow tracking | In-memory 5-tuple connection table with TCP state machine |
| Signature detection | Declarative YAML rule language with threshold gating |
| Statistical anomaly detection | EWMA volumetric spikes, port-scan, brute-force |
| Behavioral detection | DNS tunneling, HTTP attacks, data exfiltration, C2 beaconing |
| Stealth / X-Ray detection | WebRTC IP leaks, QUIC/HTTP-3, WebSockets, localhost probes, beacons, DNS prefetch storms, third-party trackers — everything the browser hides from DevTools |
| Threat intelligence | CIDR/domain IOC feeds (YAML), checked every packet |
| Alert management | Deduplication, suppression allowlists, multi-vector correlation |
| Output backends | Console (Rich), JSON (rotating file), SQLite, Syslog, **X-Ray live dashboard** |
| Hot-reload | Rules can be swapped atomically at runtime without stopping the engine |
| CLI | Click + Rich, six commands: `live`, `pcap`, `xray`, `query`, `stats`, `validate` |

---

## 2. Architecture at a Glance

```
Network Interface / PCAP File
          │
          ▼
  ┌───────────────────┐
  │   Sniffer Layer   │   sniffer.py
  │  (BPF socket /    │   • Captures raw frames
  │   PcapReader)     │   • Decodes into meta dict
  └────────┬──────────┘
           │ meta dict (src_ip, dst_ip, protocol, payload_bytes, …)
           ▼
  ┌───────────────────────────────────────────────────────┐
  │                  DetectionEngine                       │  engine.py
  │                                                       │
  │  1. dissect(meta)    ──► Protocol Dissector           │
  │     (HTTP/DNS/TLS/SSH/SMTP + STUN, QUIC, WebSocket)   │
  │  2. flow_tracker.update(meta) ──► Flow Table          │
  │  3. _run_threat_intel(meta, layer7)                   │
  │  4. for detector in [Signature, Anomaly×3,            │
  │                       Behavioral×4, Stealth×7]:       │
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
     ┌─────┼──────────┬───────────┬───────────┐
     ▼     ▼          ▼           ▼           ▼
  Console  JSON    SQLite      Syslog     XRayDashboard
  (Rich)   file    database    server     (Rich Live)
```

The engine is **single-threaded and synchronous** by design — predictable, testable, and debuggable. The only concurrency is in the sniffer layer itself: a reader thread drains the capture socket and hands raw frames to the engine thread via a bounded `queue.Queue`, so a busy engine never stalls the kernel buffer.

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
│   ├── test_signature.py
│   └── test_stealth.py             # Stealth parsers, detectors, X-Ray dashboard
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
    │       ├── syslog_out.py       # UDP/TCP syslog forwarding
    │       └── xray_dashboard.py   # Rich Live multi-panel X-Ray dashboard
    ├── detection/
    │   ├── base.py                 # BaseDetector abstract class
    │   ├── signature.py            # YAML rule engine
    │   ├── anomaly.py              # EWMA, PortScan, BruteForce detectors
    │   ├── behavioral.py           # DNS tunneling, HTTP attacks, Exfil, Beaconing
    │   └── stealth.py              # WebRTC leak, Localhost probe, QUIC, WebSocket,
    │                               #   Beacon, DNS prefetch, Tracker detectors
    ├── flow/
    │   └── tracker.py              # FlowTracker + Flow dataclass
    ├── intel/
    │   └── threat_intel.py         # ThreatIntel IOC loader & lookup
    └── protocols/
        ├── dissector.py            # HTTP, DNS, TLS, SSH, SMTP parsers + STUN/QUIC routing
        └── stealth.py              # STUN/TURN, QUIC, WebSocket, beacon parsers
```

---

## 4. Packet Capture Layer — `sniffer.py`

### 4.1 `decode_frame(frame, link, ts) → dict` and `packet_to_meta(pkt) → dict`

`decode_frame` turns the raw bytes of one captured frame into a **normalised metadata dictionary** that all downstream components consume. It is a small `struct`-based parser for Ethernet (incl. 802.1Q/QinQ VLAN tags), BSD loopback/`utun` (`DLT_NULL`), Linux cooked capture and raw IP, then IPv4 / IPv6 (extension headers, fragments), TCP, UDP, ICMP and ICMPv6 echo. The IP total length is honoured, so Ethernet padding never leaks into `payload_bytes`.

`packet_to_meta` does the same for a Scapy packet (PCAP replay, tests) by decoding `bytes(pkt)`, so replay and live capture see identical dicts.

**Why not use Scapy's dissection?** Two reasons:

1. **Correctness.** Scapy decodes the protocols it knows (DNS, mDNS, NTP, NetBIOS/SMB…) into its own layers and leaves no `Raw` payload, so the engine's DNS dissector, DNS tunnelling detector, malicious-domain intel, DNS-based tracker detection and hostname learning would never see a single live DNS packet.
2. **Speed.** Building Scapy objects costs ~105 µs per packet and `len(pkt)` re-serialises the packet. The raw decoder costs ~3 µs; the whole live path (decode → engine → live stats) measures ~23 µs per packet, roughly 44 000 packets/s per core, versus ~5 500 before.

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

### 4.2 `sniff_live(iface, engine_callback, bpf_filter, packet_queue_size, raw_callback, stop_event)`

```
Reader thread ("bpf-en0")                  Calling thread
──────────────────────────────────────────────────────────────────
select(socket, 0.5 s)                      while not stopped:
for each buffered frame:                     link, frame, ts = queue.get(0.2 s)
  raw_callback(frame, ts, linktype)          engine_callback(decode_frame(…))
  queue.put_nowait((link, frame, ts)) ────►
  (counted + dropped if queue full)
```

- Opens Scapy's platform listen socket (`conf.L2listen`: BPF on macOS, `AF_PACKET` on Linux) and reads frames with `recv_raw()`, so no Scapy packet objects are created. One BPF read can return many frames; the reader drains them all before selecting again.
- `raw_callback` receives each raw frame with its timestamp and pcap link type (the rolling PCAP recorder uses it).
- The calling thread decodes and runs the engine; it raises `OSError` if the reader dies (interface removed), which the daemon turns into a retry.
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
| 80, 8080, 8000, 8008 | HTTP | `_parse_http` (+ WebSocket / beacon flags) |
| 443, 8443 | TLS | `_parse_tls_client_hello` |
| 22 | SSH | `_parse_ssh_banner` |
| 25, 465, 587 | SMTP | `_parse_smtp` |

In addition, **before** any port-based routing, every UDP datagram is run through two **port-independent probes** (`protocols/stealth.py`):

1. `is_stun(payload)` — checks the STUN magic cookie at offset 4. If it matches, `_parse_stun` is called and `layer7["stun"]` is populated.
2. `is_quic(payload)` — checks the long-header bit pattern + version field. Successful matches populate `layer7["quic"]`.

This is essential: WebRTC and HTTP/3 routinely fly over arbitrary UDP ports (3478, 19302, 50000+, 443, …) and a port-only router would miss them.

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

### 5.7 Stealth-Protocol Parsers (`protocols/stealth.py`)

This module powers the **X-Ray** detection layer. It contains four pure-Python decoders for transports that the browser's DevTools Network tab does **not** show.

#### `parse_stun(payload) → dict`  (RFC 5389 / RFC 8489)

A complete STUN/TURN message decoder.

- **Magic cookie check** at offset 4 (`0x2112A442`) acts as a port-independent classifier.
- Walks the TLV attribute list and decodes:
  - `XOR-MAPPED-ADDRESS` (type `0x0020`) — IPv4 and IPv6, with the full RFC 5389 §15.2 XOR scheme (port XORed with the upper 16 bits of the magic cookie; IPv6 address XORed with magic ‖ transaction-ID).
  - `XOR-RELAYED-ADDRESS` (type `0x0016`) — TURN-allocation responses.
  - `MAPPED-ADDRESS` (type `0x0001`) — legacy plain-text address.
  - `SOFTWARE` (type `0x8022`) — server identity string.
  - `USERNAME` (type `0x0006`) — short-term-credential username.
- Output keys: `message_type`, `txid`, `is_response`, `is_error`, `is_turn`, `software`, `addresses`, `mapped_address`.

#### `parse_quic(payload) → dict`  (RFC 9000 long-header probe)

- Checks the **long-header bit pattern** `0b11xxxxxx` at byte 0 (the long-header bit and the fixed bit) before reading the 32-bit version field.
- Recognises QUIC v1 (`0x00000001`), v2 (`0x6B3343CF`), draft-29 (`0xFF00001D`), version-negotiation (`0x00000000`), and Quicly drafts.
- Extracts long-header packet type (Initial / 0-RTT / Handshake / Retry), Destination Connection ID, and Source Connection ID.
- Output keys: `version`, `version_code`, `packet_type`, `dcid`, `scid`.

#### `is_websocket_upgrade(http_info) → bool`

Returns true when the dissected HTTP request carries `Upgrade: websocket` **and** `Connection: upgrade` (case-insensitive). Used by the dissector to add `websocket_upgrade: true` to the `http` dict and consumed by the `WebSocketDetector`.

#### `is_beacon_request(http_info) → bool`

Heuristic that flags fire-and-forget HTTP requests typical of `navigator.sendBeacon` and 1×1 tracking pixels:

- POSTs ≤ 1500 bytes with a beacon-family `Content-Type` (`text/plain`, `application/json`, `application/x-www-form-urlencoded`, or empty) **and** no `Accept` header.
- GETs whose path matches a curated hint list (`/beacon`, `/collect`, `/__utm.gif`, `/pixel`, `/cdn-cgi/rum`, …) or `*.gif?…` URLs that are clearly tracking pixels.

#### `classify_ip(ip) → str`

Convenience wrapper around `ipaddress` that returns one of `'loopback'`, `'private'`, `'link_local'`, `'multicast'`, `'public'`, `'unknown'`. The X-Ray dashboard uses it to colour-code leaked addresses, and the `LocalhostProbeDetector` uses it as its primary gate.

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
   - **Stealth pack** (gated by `stealth.enabled`, default `true`):
     - `WebRtcLeakDetector`
     - `LocalhostProbeDetector`
     - `QuicHttp3Detector`
     - `WebSocketDetector`
     - `BeaconDetector`
     - `DnsPrefetchDetector`
     - `TrackerDetector` (gated by `stealth.trackers_enabled`)

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

Monitors connection **attempts** to authentication services: only the first packet of a flow counts, and for TCP only a SYN without ACK, so the packets inside one busy SSH session never add up. Maintains a `deque[float]` of timestamps per `(src_ip, dst_ip, dst_port)` key.

Alert condition: `len(bucket_within_window) >= threshold`

Severity depends on direction: attempts **against this machine** are **HIGH** ("Brute force on SSH"); many connections **from this Mac** to a remote service are **MEDIUM** ("Many SSH connections"), because that is usually tooling such as git over SSH.

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

Only **new connections to public internet addresses** count. Skipped by design: loopback, link-local and private-LAN destinations (AirPlay receivers, printers, DHCPv6 housekeeping), multicast/broadcast, DNS/NTP/mDNS ports, and macOS system daemons. A daemon is "system" when its executable lives under `/System/`, `/usr/libexec/`, `/usr/sbin/` or `/sbin/`, the SIP-protected system volume malware cannot write to. `/usr/bin` is deliberately excluded because `curl`, `python` and `nc` there can be driven by anything.

Severity: **MEDIUM** when the server has a hostname learned from DNS/SNI (mail sync, update checks, telemetry); **HIGH** when the app polls a **bare IP it never looked up**, the more C2-like pattern.

Confidence: `max(0, 1.0 - cv / cv_threshold)` — a CV of 0 gives confidence 1.0.

**MITRE:** `T1071`

### 8.4 Stealth / X-Ray Detection

**File:** `detection/stealth.py`

The DevTools "Network" tab is a curated view: it shows the renderer's own `fetch`/`XHR` calls and very little else. The stealth pack surfaces every category of activity the browser performs **outside** that view, so the operator finally sees what their machine is doing on their behalf.

All stealth detectors emit `BEHAVIORAL` alerts with `rule_id` strings starting with `STEALTH-…`, so they sit naturally alongside the rest of the alert ecosystem and can be persisted, queried, suppressed, and correlated identically.

#### `WebRtcLeakDetector` — STUN / TURN IP-leak surveillance

For every UDP datagram dissected as STUN, the detector inspects `XOR-MAPPED-ADDRESS` (binding response) and `XOR-RELAYED-ADDRESS` (TURN allocation):

- If the leaked address is `loopback` / `private` / `link_local` → **HIGH** severity `STEALTH-WEBRTC-LEAK`. This is the textbook "WebRTC IP leak" that bypasses VPN/proxy tunnels.
- If the leaked address is `public` → **LOW** severity `STEALTH-WEBRTC-REFLEXIVE` (the browser still revealed the user's public IP to a third-party STUN server outside any visible page traffic).
- If the message is a Binding Request with no mapped address yet → **LOW** severity `STEALTH-WEBRTC-STUN` (or `STEALTH-WEBRTC-TURN` for TURN methods) — purely informational, useful for the dashboard's "WebRTC peers" panel.

**MITRE:** `T1592.004` (Gather Victim Host Information: Identify Network Configuration)

#### `LocalhostProbeDetector` — Browser-side fingerprinting

Detects the well-documented technique of webpages probing `127.0.0.1` (and RFC1918 ranges) to fingerprint locally-running developer tools, password managers, malware-analysis sandboxes, etc.

The detector is gated tightly to avoid false-positive storms. Severity depends on **who opened the connection** (from process attribution):

| Initiator | Single probe | Port sweep (`scan_threshold` distinct ports in `scan_window`) |
|---|---|---|
| Browser (confirmed) | **HIGH** loopback / **MEDIUM** LAN | **CRITICAL** |
| Unidentified (closed before the socket table was sampled) | **MEDIUM** loopback / **LOW** LAN, rate-limited | **HIGH**, ephemeral destination ports not counted |
| Native app | silent | **HIGH**, ephemeral destination ports not counted |

Ignored entirely:

- Anything but a **TCP SYN without ACK** (genuine connection initiations). UDP only counts when a browser sends it: web pages can't send raw UDP, and the LAN broadcasts/discovery chatter it would otherwise flag come from the OS.
- **Local IPC pairs**: both ports ephemeral (≥ 49152) and within 4 of each other, i.e. a program connecting to a socket it opened a moment earlier.
- PyNIDS's own API/dashboard port, broadcast/multicast destinations, and quiet OS ports on private subnets (`mDNS:5353`, `dhcp:67/68`, `https:443` to the gateway…).
- Repeats of the same `(app, destination, port)` within `repeat_cooldown` (1 h). The next alert reports how many attempts were suppressed, so timer-driven health checks show up once rather than every few minutes.

Evidence includes `initiator` and `target_app` (the program listening on the probed port, when known).

**MITRE:** `T1046` (Network Service Discovery)

#### `QuicHttp3Detector` — HTTP/3 endpoint surfacing

Emits a single `STEALTH-QUIC-INITIAL` alert per unique `(src_ip, dst_ip, dst_port)` whenever a QUIC long-header **Initial** packet is observed. Subsequent packets of the same connection are silently swallowed. This gives the X-Ray panel a clean list of HTTP/3 endpoints without flooding the alert stream.

**MITRE:** `T1071.001`

#### `WebSocketDetector` — Long-lived bi-directional channels

When the dissector sets `layer7.http.websocket_upgrade = true`, this detector emits a `STEALTH-WEBSOCKET` alert carrying `host`, `path`, and (truncated) `user_agent` in the evidence dict.

#### `BeaconDetector` — `navigator.sendBeacon` and tracking pixels

Triggered by the `layer7.http.beacon_suspect` flag set by the dissector. Emits a `STEALTH-BEACON` alert with the full request line and content metadata. Severity is **LOW** because beacons are pervasive; the detector's value is **visibility**, not severity.

#### `DnsPrefetchDetector` — Page-load DNS storms

Maintains a per-`src_ip` deque of `(timestamp, query_name)` samples within a sliding `window_seconds` (default 5 s). When the deque holds at least `burst_threshold` (default 8) **distinct** names, a `STEALTH-DNS-PREFETCH` alert is emitted with up to 20 of the unique hosts in the evidence. A cool-down equal to the window prevents alert flooding while the burst is ongoing.

This is the fingerprint of `<link rel="dns-prefetch">` / `<link rel="preconnect">` browser hints firing the moment a page starts loading — none of which appear in DevTools.

#### `TrackerDetector` — Built-in third-party tracker list

Maintains a curated dictionary of ~60 well-known analytics / advertising / RUM domains (Google Analytics, Meta Pixel, DoubleClick, Hotjar, FullStory, Sentry RUM, Datadog RUM, Segment, Mixpanel, Amplitude, …). The detector matches on three signal sources, in priority order:

1. TLS SNI (`layer7.tls.sni`)
2. HTTP `Host` (`layer7.http.host`)
3. DNS query name (`layer7.dns.query_name`, requests only)

Domain matches are **suffix-based** — `doubleclick.net` matches `stats.g.doubleclick.net` but not `notdoubleclick.net`. Each `(src_ip, host)` is reported at most once via a `_reported` set, keeping the stream concise.

The domain list is overridable: pass a custom `domains={"my.tracker.example": "Internal"}` dict to the constructor.

#### Summary of stealth rule IDs

| Rule ID | Default Severity | MITRE | Detector |
|---|---|---|---|
| `STEALTH-WEBRTC-LEAK` | HIGH | T1592.004 | `WebRtcLeakDetector` |
| `STEALTH-WEBRTC-REFLEXIVE` | LOW | T1592.004 | `WebRtcLeakDetector` |
| `STEALTH-WEBRTC-STUN` | LOW | T1071 | `WebRtcLeakDetector` |
| `STEALTH-WEBRTC-TURN` | LOW | T1071 | `WebRtcLeakDetector` |
| `STEALTH-LOCALHOST-PROBE` | HIGH (loopback) / MEDIUM (private) | T1046 | `LocalhostProbeDetector` |
| `STEALTH-LOCALHOST-SCAN` | CRITICAL | T1046 | `LocalhostProbeDetector` |
| `STEALTH-QUIC-INITIAL` | LOW | T1071.001 | `QuicHttp3Detector` |
| `STEALTH-WEBSOCKET` | LOW | T1071.001 | `WebSocketDetector` |
| `STEALTH-BEACON` | LOW | T1071.001 | `BeaconDetector` |
| `STEALTH-DNS-PREFETCH` | LOW | T1071.004 | `DnsPrefetchDetector` |
| `STEALTH-TRACKER` | LOW | T1071.001 | `TrackerDetector` |

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

#### Plain-English guide — `alerts/guide.py`

`describe(alert_dict)` returns what a non-specialist needs to read an alert, written from the alert's own evidence and context (which app, which host, how often):

| Key | Example |
|---|---|
| `summary` | "Microsoft Outlook contacts outlook.office365.com every 16 minutes, very regularly." |
| `meaning` | What this kind of event is, its common benign causes, and when it would matter |
| `verdict` | `Usually harmless` · `Privacy` · `Worth checking` · `Act now` |
| `next_steps` | Concrete actions, e.g. "Run `sudo lsof -nP -iTCP:1337` when it happens" |
| `details` | Readable evidence rows (`("Interval", "every 16 minutes")`, `("Listening app", "node")`) |

The API attaches it as `about` to every alert (`/api/alerts`, `/api/alerts/<id>`, the live SSE stream), and the brief used by the widget carries `summary` and `verdict`. The dashboard drawer shows it above the connection details (raw evidence JSON is collapsed below), the event list shows the summary and verdict pill, the menu bar shows them with the full explanation on hover, and macOS notifications use the summary as the banner text and the verdict as the subtitle. It is local and instant; "Explain with Claude" remains the deeper, per-event analysis.

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
| `XRayDashboard` | `outputs/xray_dashboard.py` | Multi-panel Rich Live terminal dashboard for stealth-class alerts. See § 10.4. |

### 10.4 X-Ray Live Dashboard

**File:** `alerts/outputs/xray_dashboard.py`

`XRayDashboard` is the visual centrepiece of `pynids xray`. It is a regular `BaseOutput` that the `AlertManager` dispatches every alert to, but instead of printing each event as a single line it **maintains an in-memory model of every category of stealth event** and renders the model into a multi-panel layout that refreshes several times per second.

#### Architecture

```
AlertManager.add(alert)
        │
        ▼
emit(alert)  ──► classify (kind ∈ {webrtc, localhost, quic, websocket,
        │                          tracker, beacon, prefetch, other})
        │       update per-panel state under self._lock
        │
Background "xray-render" thread (daemon):
   while not stop_event:
       sleep(1 / refresh_hz)
       Live.update(self._render())
```

The render thread reads the same protected state that `emit()` writes; both sides hold `self._lock` (an `RLock`) for the brief duration of their data accesses. Rendering itself happens **outside** the lock — Rich computes the layout from the snapshot it just read, not from the live data structures.

#### Layout

```
┌─ banner — name, interface, uptime, hidden-event counters ─┐
├──────────────────────────┬─────────────────────────────────┤
│ WebRTC / IP leaks        │ Localhost / private probes      │
├──────────────────────────┼─────────────────────────────────┤
│ QUIC / HTTP-3 endpoints  │ WebSocket sessions              │
├──────────────────────────┴─────────────────────────────────┤
│ Trackers · Beacons · Prefetch                              │
├────────────────────────────────────────────────────────────┤
│ Live event stream — newest at the bottom                   │
└────────────────────────────────────────────────────────────┘
```

| Panel | Aggregation key | Surfaces |
|---|---|---|
| **WebRTC / IP leaks** | `(src_ip, dst_ip, leaked_ip)` | Newest leaks first; private/loopback IPs highlighted in bold red, public reflexive addresses in cyan |
| **Localhost / private probes** | `(src_ip, dst_ip, dst_port)` | Probes coloured by destination class; full port list shown when a `STEALTH-LOCALHOST-SCAN` lands |
| **QUIC / HTTP-3** | `(src_ip, dst_ip)` | One row per destination with version detected and packet count |
| **WebSocket sessions** | `(src_ip, host)` | Host + path + count |
| **Trackers · Beacons · Prefetch** | `(src_ip, host)` | Top-8 trackers by hit count plus running beacon and prefetch totals |
| **Live event stream** | rolling deque (200) | Last 25 events shown chronologically |

#### Constructor parameters

| Parameter | Default | Purpose |
|---|---|---|
| `iface` | `"?"` | Cosmetic banner label (set to the interface or `pcap:<file>` by the CLI). |
| `refresh_hz` | `6.0` | Render rate; 4–6 Hz feels live without flicker. |
| `max_stream` | `200` | Cap on the rolling event deque. |
| `max_per_panel` | `12` | Rows kept (and panel height seed) for the four top panels. |
| `console` | `None` | Inject a `rich.console.Console` (used in tests with `record=True`). |

#### Lifecycle

`start()` creates a `rich.live.Live` in `screen=True` mode (alternate-buffer fullscreen) and spawns the daemon render thread. `close()` sets the stop event, joins the render thread, performs a final paint, and stops the `Live` so the previous terminal contents are restored cleanly.

The CLI's `pynids xray` command always wraps both calls in a `try/finally` so the user's terminal is never left in a corrupted state.

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

### `pynids xray`
```
pynids xray --iface en0 \
            [--bpf "..."] [--pcap capture.pcap] \
            [--also-localhost / --no-localhost] [--loopback-iface lo0] \
            [--refresh 6.0] [--json-log xray.jsonl] [--sqlite alerts.db] \
            [--config configs/enterprise.yaml] [--rules rules/...]
```

Runs the full detection pipeline with the stealth pack enabled and replaces the per-line console output with the multi-panel **X-Ray live dashboard** (`XRayDashboard`).

Implementation notes:

- Forces `cfg["stealth"]["enabled"] = true` regardless of config defaults.
- Builds a fresh `AlertManager` with `dedup_window=0` so the dashboard can show every event verbatim. The `correlation_threshold` is intentionally raised out of reach (999) — multi-vector correlation is meaningless for a privacy-monitoring view.
- When `--also-localhost` is set (default) **and** the primary interface is not the loopback, a second `sniff_live` thread is started on the loopback device so the dashboard can detect browser-initiated connections to `127.0.0.1`, which never leave the host's main NIC.
- `--pcap` runs `replay_pcap()` to completion and then keeps the dashboard alive (a sleep loop) until the user hits Ctrl-C. This lets the operator read the result without the terminal screen being torn down immediately.
- `--json-log` and `--sqlite` register additional `BaseOutput` backends in parallel with the dashboard, so the same events are simultaneously persisted.
- All capture is gracefully torn down in a `try/finally` that calls `dashboard.close()` and `alert_manager.close()`.

Requires **root/administrator privileges** when sniffing live (raw socket access). PCAP replay runs without privileges.

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

stealth:
  enabled: true                   # Master switch for the whole stealth pack
  trackers_enabled: true          # Match against the built-in tracker domain list
  scan_threshold: 5               # Distinct localhost ports → scan alert
  scan_window: 30.0               # Sliding window for localhost-scan check (s)
  dns_prefetch_threshold: 8       # Distinct DNS lookups in burst window
  dns_prefetch_window: 5.0        # Burst window in seconds

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
                       │  • UDP first → is_stun()? is_quic()?  (port-independent)
                       │  • else port-routed → HTTP/DNS/TLS/SSH/SMTP
                       │  • layer7 = {
                       │      app_proto: "http",
                       │      http: {uri, method, sqli_suspect: true,
                       │             websocket_upgrade?, beacon_suspect?},
                       │      stun?: {message_type, mapped_address: {…}},
                       │      quic?: {version, packet_type, dcid, scid},
                       │      …
                       │    }
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
13.            WebRtcLeakDetector.analyze(meta, layer7.stun, …)
14.            LocalhostProbeDetector.analyze(meta, …)
15.            QuicHttp3Detector.analyze(meta, layer7.quic, …)
16.            WebSocketDetector.analyze(meta, layer7.http, …)
17.            BeaconDetector.analyze(meta, layer7.http, …)
18.            DnsPrefetchDetector.analyze(meta, layer7.dns, …)
19.            TrackerDetector.analyze(meta, layer7.{tls,http,dns}, …)
                       │
                       │  alerts = [Alert(SIGNATURE, CRITICAL, …),
                       │            Alert(BEHAVIORAL, HIGH, "STEALTH-WEBRTC-LEAK"), …]
                       ▼
20.            AlertManager.add(alert) for each alert
                   A. Severity gate → pass
                   B. Suppression check → not suppressed
                   C. Dedup check → first occurrence, not duplicate
                   D. Dispatch to ConsoleOutput / JsonFileOutput /
                      SQLiteOutput / XRayDashboard
                   E. Update correlation window → no correlation yet
                       │
                       ▼
21.            Terminal / JSON file / SQLite / Syslog / X-Ray dashboard
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
| `test_stealth.py` | STUN encode/decode round-trip, QUIC long-header recognition, WebSocket / beacon heuristics, every stealth detector with canonical positive/negative inputs, X-Ray dashboard ingest classification, render-doesn't-raise smoke tests |

Total: **139 tests** (105 pre-existing + 34 stealth).

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
| **Port-independent STUN / QUIC probes** | WebRTC and HTTP/3 routinely use random high UDP ports; classifying by magic-cookie / long-header bits rather than port is the only way to catch them reliably. |
| **Stealth detectors emit `BEHAVIORAL` alerts with `STEALTH-…` rule IDs** | Reuses the entire alert-management, persistence, and querying ecosystem instead of inventing a parallel pipeline. The X-Ray dashboard is just another `BaseOutput`. |
| **X-Ray dashboard runs on a daemon render thread** | Decouples render rate from packet rate. The engine's hot path remains dedup-free and deterministic; the dashboard re-renders at a fixed Hz no matter how busy the wire is. |
| **Dual sniffer (main NIC + loopback) in `pynids xray`** | Loopback packets never traverse the primary interface, so a second `sniff_live` thread on `lo`/`lo0` is required to detect browser-side localhost probes. |
| **Hash-indexed threat intel** | Live feeds bring thousands of indicators. IPs are indexed per (version, prefix length) and domains by exact name and label suffix, so a lookup costs ~4 µs whatever the feed size. |
| **Passive hostname learning instead of reverse DNS** | DNS answers, SNI, and Host headers name the service the machine *meant* to reach; PTR records return opaque CDN node names and cost a network round trip. |
| **Process attribution by (transport, local port)** | Ports are unique per transport on a host, including `0.0.0.0` UDP binds used by QUIC; the socket table is snapshotted off-thread so packet lookup is a dict access. |

---

## 17. Version 2: Always-On Service, Enrichment & Response

Version 2 turns PyNIDS from a foreground CLI into a background service with native macOS
front ends. Everything below runs only on live traffic from the local machine.

### 17.1 New modules

| Module | Responsibility |
|---|---|
| `protocols/quic_crypto.py` | RFC 9001/9369 Initial key derivation, header-protection removal, AES-GCM decryption, CRYPTO-frame parsing, multi-packet ClientHello reassembly |
| `protocols/dissector.py` (`_TlsRecordAssembler`) | Buffers a TLS ClientHello record split across TCP segments (post-quantum key shares exceed one MSS) |
| `enrich/process.py` | `ProcessResolver`: background psutil socket snapshots → `(proto, local_port) → {pid, process, app, exe, user}`; mappings survive 5 min after socket close |
| `enrich/hostnames.py` | `HostnameCache`: bounded LRU IP → hostname from DNS answers, TLS/QUIC SNI, HTTP Host |
| `enrich/geo.py` | `GeoResolver` over DB-IP City/ASN Lite `.mmdb`; `download_databases()` |
| `enrich/__init__.py` | `Enricher.packet_context()` → `{direction, remote_ip, app, process, pid, remote_host, country, city, lat, lon, asn, org}` |
| `intel/feeds.py` | Feed registry, parsers, atomic JSON cache, `load_into()`, `load_trackers()`, `load_doh()` |
| `detection/stealth.py` (`DohDetector`) | Encrypted-DNS sessions by SNI, port 853, or HTTPS to known resolver IPs |
| `alerts/classify.py` | Maps alerts to UI "kinds" (threat, attack, webrtc, localhost, doh, tracker, beacon, websocket, quic, prefetch) |
| `response/pf.py` | `PfBlocker` (pf anchor `com.apple/250.PyNIDS`, table `<pynids_block>`, JSON ledger, expiry, guard rails) and `AutoBlockPolicy` output |
| `response/notify.py` | `NotificationOutput`: coalesced macOS banners posted into the console user's session via `launchctl asuser` |
| `ai/explain.py` | Claude Opus 5 alert explanations (official `anthropic` SDK, server-side refusal fallback, untrusted-data framing) |
| `service/live.py` | `LiveState`: packet observer + alert output; per-app and per-endpoint accounting, rate history, 60-minute timeline, SSE fan-out |
| `service/api.py` | Stdlib `ThreadingHTTPServer` API + dashboard; Host allowlist, token, Origin check |
| `service/daemon.py` | Assembles engine, enrichment, outputs, API, capture threads, feed refresh, interface watchdog |
| `service/launchd.py` | LaunchDaemon plist install / uninstall / restart |
| `service/recorder.py` | Rolling PCAP ring for the key-log decryption workflow |
| `web/dashboard.html` | Single-file dashboard (vanilla JS + SVG charts, d3-geo map) |
| `cli_service.py` | `daemon`, `status`, `open`, `intel`, `geoip`, `block`, `ai`, `keylog`, `decrypt`, `app` |
| `macos/src/` | SwiftUI menu bar app + WidgetKit extension, built by `macos/build.sh` with `swiftc` |

### 17.2 Packet journey (v2)

```
sniff_live(en0) ─┐
sniff_live(lo0) ─┴─► DetectionEngine.process_packet(meta)
                      1  dissect()            ← TLS reassembly, QUIC decryption, DNS answers
                      1b Enricher.packet_context() → context
                      2  FlowTracker.update()
                      3  threat intel         ← IP, DNS name, TLS/QUIC SNI
                      4  detectors            ← 16 including DohDetector
                         alert.context = context
                         LiveState.observe_packet(meta, layer7, context)
                      5  AlertManager.add() → LiveState · SQLiteOutput · NotificationOutput · AutoBlockPolicy
```

### 17.3 Local API

| Route | Auth | Purpose |
|---|---|---|
| `GET /` | — | Dashboard (token injected) |
| `GET /api/health` | — | Liveness |
| `GET /api/widget` | — | Counts + latest alert headline for the sandboxed widget |
| `GET /api/summary` | token | Counts by kind/severity, rates, top apps, status, threat level |
| `GET /api/alerts?limit&min_severity&kind&q&app&since&until` | token | History from SQLite (FTS5 search) |
| `GET /api/alerts/{id}` | token | One alert |
| `GET /api/apps`, `/api/remotes`, `/api/timeline` | token | Live traffic views |
| `GET /api/stream` | token (query) | Server-Sent Events: `alert`, `tick`, `block`, `unblock`, `intel` |
| `GET/POST /api/blocks`, `DELETE /api/blocks/{ip}` | token + Origin | pf blocks |
| `POST /api/explain/{id}` | token + Origin | Claude explanation (cached in `explanations` table) |
| `GET /api/intel`, `POST /api/intel/update` | token (+ Origin) | Feed status / refresh and hot-reload |
| `POST /api/notifications` | token + Origin | Pause / resume banners |

### 17.4 Files on disk

| Path | Contents |
|---|---|
| `/Library/LaunchDaemons/com.pynids.daemon.plist` | launchd job |
| `/Library/Application Support/PyNIDS/config.yaml` | Daemon config |
| `…/events.db` | Alerts (+ `explanations` table), WAL mode |
| `…/intel/*.json` | Cached feeds |
| `…/geoip/*.mmdb` | DB-IP databases |
| `…/api-token` | API token (0644) |
| `…/anthropic-key` | Claude API key (0600) |
| `…/blocklist.json` | Block ledger |
| `…/captures/*.pcap` | Rolling capture window (only with `--record`) |
| `/Library/Logs/PyNIDS/daemon.log` | Daemon log |

### 17.5 Known limits

* The very first packet of a brand-new connection can be unattributed if the socket opened
  and closed between two socket-table snapshots (1.5 s apart).
* SNI cannot be read when Encrypted Client Hello is used; the alert then carries the outer
  public name and `ech: true`.
* The desktop widget refreshes on WidgetKit's schedule (the menu bar app nudges it when
  events arrive); the menu bar and dashboard are the live views.
* The menu bar app is ad-hoc signed. It runs on the Mac that built it; distributing it
  needs a Developer ID signature and notarization.

---

## 18. Host Inspection: Programs, Persistence, IP Dossiers, LAN, Claude Investigation

Packets say *what* happened; `pynids/host/` says *who* did it and whether to trust them.

### 18.1 Modules

| Module | Role |
|---|---|
| `host/codesign.py` | `SignatureChecker` runs `codesign -dv` + `codesign --verify` (not `--strict`, which rejects harmless layouts in signed apps such as Teams) on a background thread, cached per (path, size, mtime). `lookup()` never blocks. `path_risk()` judges the location; `assess()` combines both into flags and a 0–3 risk. Dev-tool locations (Homebrew, `.venv`, `.nvm`, `node_modules` …) don't count as untrusted, because ad-hoc linker signatures are normal there |
| `host/connections.py` | psutil socket table + `nettop` user-space flows (with remote endpoints). UDP sockets on ephemeral ports (≥ 49152) with no peer are client sockets, not listeners |
| `host/persistence.py` | Reads every LaunchAgent / LaunchDaemon plist; `PersistenceIndex.for_program()` maps an executable (or anything in its `.app` bundle) to the jobs that start it |
| `host/dossier.py` | `IpLookup`: PTR, RDAP (`rdap.org`) and Shodan InternetDB, concurrently, cached 24 h in `ip_lookups` (events DB). Never sent for non-global addresses. `LookupPrefetch` (alert output) queues automatic lookups per `lookups.mode`, capped at 40/hour |
| `host/lan.py` | `LanInventory` from `arp -an` + hostname cache, persisted in `lan_devices`; `LAN-NEW-DEVICE` after the learning window. `run_nmap()` (`-sV --top-ports 200`) only for private / link-local / own addresses |
| `host/inspector.py` | `HostInspector` joins everything for the API, CLI and Claude tools. The connection table is single-flight cached (3 s); programs are grouped by outermost `.app` bundle |

### 18.2 Detectors (`detection/hostrisk.py`)

* **`ProcessRiskDetector`**: once per executable, on its first outbound packet to a public IP after its signature is known. The enricher adds `exe` and `signature` to every packet context.
* **`BaselineDetector`** with `BaselineStore` (`baseline` table): silent for `baseline_learning_hours`; afterwards `HOST-NEW-PROGRAM` for unseen executables and `BASELINE-NEW-COUNTRY` for non-browser apps known longer than the learning window.
* **`C2Correlator`**: an alert *output* that re-injects into `AlertManager.add`. Signals are kept per program (`untrusted_binary`, `new_program`) and per remote (`beacon`, `bare_ip`, `intel`, plus `c2_infra` from cached InternetDB tags). It fires `HOST-C2-LIKELY` when there are ≥ 2 distinct signals (not counting `bare_ip`), at least one network-side, once per (program, remote) per 6 h.

### 18.3 Allowlist (`alerts/allowlist.py`)

"Mark as expected" rules (`kind`, `rule_id`, `app`, `host` with subdomain match, `ip`) in
`allowlist.json`, applied through the new `AlertManager.add_filter()` hook before dedup and
outputs. A rule with only `kind: threat` or `kind: attack` is refused as too broad.

### 18.4 Claude

* `ai/explain.py` uses `claude-opus-5-5` with `output_config.effort: high` (Opus 5.5 defaults to `medium`) and server-side `fallbacks: "default"`. The daemon passes `host_context` (program signature + launch items, IP dossier) with the alert.
* `ai/investigate.py` is a manual tool-use loop (max 14 turns) over eight strict, read-only tools backed by `HostInspector`. The full `response.content` is appended each turn (append-only history); tool failures go back as `is_error` results; tool output is capped at 24 kB and framed as untrusted data in the system prompt. Only one investigation runs at a time (`409` otherwise).

### 18.5 API additions

`GET /api/attention`, `/api/connections`, `/api/program?exe=`, `/api/dossier/<ip>[?external=1&refresh=1]`,
`/api/launch-items`, `/api/devices`, `POST /api/devices/scan`, `GET|POST /api/allowlist`,
`DELETE /api/allowlist/<id>`, `POST /api/investigate`, `GET /api/apps/<name>`, `GET /api/baseline`,
and unauthenticated `GET /static/<file>` for the vendored map libraries (flat allowlist of
`.js` / `.json` names). The server's listen backlog is raised to 128, because the dashboard
opens more parallel requests than socketserver's default of 5.

