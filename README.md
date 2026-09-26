<div align="center">

# 🛡️ PyNIDS

### Network intrusion detection and privacy X-Ray for your Mac

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#-license)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/tests-201%20passing-brightgreen.svg)]()

PyNIDS watches your Mac's real network traffic and tells you, in plain language, what is
going on. It catches attacks and connections to known-malicious servers. It also shows
what browsers and apps do quietly behind your back: trackers, WebRTC IP leaks, webpages
port-scanning your machine, DNS hidden inside HTTPS, and more. For every connection you see
**which app** made it and **where in the world** it went.

It runs as an always-on background service, with a **web dashboard**, a **menu bar app**,
a **desktop widget**, **native notifications**, one-click **blocking**, and optional
**"Explain with Claude"** for any alert.

</div>

---

## Contents

1. [What you get](#-what-you-get)
2. [Requirements](#-requirements)
3. [Installation (step by step)](#-installation-step-by-step)
4. [Everyday use](#-everyday-use)
5. [Updating & restarting](#-updating--restarting)
6. [Understanding the alerts](#-understanding-the-alerts)
7. [How it works](#-how-it-works)
8. [Blocking, Claude & decryption](#-blocking-claude--decryption)
9. [Configuration](#-configuration)
10. [Command reference](#-command-reference)
11. [Privacy & security](#-privacy--security)
12. [Troubleshooting](#-troubleshooting)
13. [Uninstall](#-uninstall)
14. [For developers](#-for-developers)

---

## ✨ What you get

### Detection

| | |
|---|---|
| **Attacks & anomalies** | Port scans and host sweeps, brute force (SSH, RDP, VNC, mail …), SQL injection / XSS / path traversal, DNS tunnelling, C2 beaconing, large uploads, unsolicited traffic floods, and 20+ MITRE-tagged signature rules |
| **Live threat intelligence** | Every IP, DNS name, and TLS/QUIC hostname is checked against abuse.ch Feodo (botnet C2) and URLhaus (malware), Spamhaus DROP, and Tor exit lists, refreshed every 6 hours |
| **Correlation** | Several different attack signatures from one source become a single CRITICAL "multi-vector attack" alert |

### Privacy X-Ray: what DevTools doesn't show you

| | |
|---|---|
| **WebRTC IP leaks** | STUN responses that reveal your private or public IP, even behind a VPN |
| **Localhost probing** | Webpages port-scanning `127.0.0.1` or your LAN to fingerprint installed software |
| **Trackers** | 4,000+ ad, analytics, fingerprinting, and crypto-mining domains (Disconnect list) |
| **Encrypted DNS** | DNS-over-HTTPS / TLS / QUIC sessions that bypass your system resolver |
| **QUIC / HTTP-3, WebSockets, beacons, prefetch storms** | Background connections that never show up in the browser's Network tab |

### Visibility inside encrypted traffic

* **QUIC decryption.** PyNIDS decrypts the first packet of every HTTP/3 connection (RFC 9001) to read which site it is for. Your data stays encrypted; only the handshake is read.
* **TLS reassembly.** Modern post-quantum handshakes are split across several packets. PyNIDS stitches them back together to read the hostname, ALPN, and whether Encrypted Client Hello is in use.
* **Hostnames everywhere.** IPs are turned back into names using the DNS answers and handshakes your Mac already sees, not reverse DNS.

### Context on every event

* **Which app.** Every connection is tagged with the app that made it. Helper processes are folded into their app ("Google Chrome Helper" → "Google Chrome", WebKit → "Safari / WebKit"). Safari and WhatsApp use Apple's user-space network stack, which normal socket tools can't see, so PyNIDS also reads macOS's `nettop`.
* **Where.** Country, city, and network owner (ASN) from the free offline DB-IP database.

### Ways to see it

| | |
|---|---|
| **Web dashboard** | `http://127.0.0.1:8787`: live throughput, events per minute, a world map of every endpoint, per-app traffic, a searchable event stream, blocking, and feed status |
| **Menu bar app** | Shield icon that changes colour with the threat level; popover with stats, a throughput graph, recent alerts, and busiest apps |
| **Desktop widget** | Small / medium / large. Headlines what needs attention *in the last hour*, or "All clear" |
| **Notifications** | macOS banners for HIGH and CRITICAL alerts; bursts are grouped into one banner |
| **Terminal** | `pynids status`, and the live full-screen `pynids xray` dashboard |

### Response

* **Blocking** through macOS's built-in `pf` firewall, from the dashboard, menu bar, or CLI. Optionally automatic for confirmed threats, with guard rails and expiry.
* **Explain with Claude.** One click turns an alert into a verdict, an explanation, and next steps.
* **HTTPS decryption workflow.** Launch a browser that logs its TLS keys, record traffic, and list the decrypted requests.

---

## 📋 Requirements

* **macOS 14 (Sonoma) or newer.** Linux works for the CLI tools; the background service, menu bar app, and widget are macOS-only.
* **Python 3.9+.** The one that comes with macOS is fine.
* **Admin password.** Capturing packets and managing the firewall need `sudo`.
* **Xcode Command Line Tools** for the menu bar app and widget: `xcode-select --install`. Full Xcode is *not* needed.
* Optional: an **Anthropic API key** for "Explain with Claude", and **Wireshark** (`brew install --cask wireshark`) for the decryption workflow.

---

## 🚀 Installation (step by step)

### 1. Get the code and install it

```bash
git clone https://github.com/Rarees404/NIDS.git ~/NIDS
cd ~/NIDS

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip     # macOS ships an old pip that can't install this project
pip install -e ".[all]"       # core + GeoIP + Claude support
```

### 2. Start the background service

```bash
sudo .venv/bin/pynids daemon install
```

This starts PyNIDS now and at every boot. It watches your active connection (Wi-Fi,
Ethernet, or VPN, and it follows you when you switch) plus `lo0` for localhost probing.
Threat-intel feeds download automatically on first start.

> Use the full path `.venv/bin/pynids` with `sudo`, because `sudo` doesn't see your
> virtual environment. Commands without `sudo` can just use `pynids` while the venv is active.

### 3. Turn on the world map (recommended)

```bash
sudo .venv/bin/pynids geoip download       # free DB-IP Lite databases, about 70 MB
sudo .venv/bin/pynids daemon restart
```

### 4. Open the dashboard

```bash
pynids open            # opens http://127.0.0.1:8787
pynids status          # one-screen summary in the terminal
```

### 5. Install the menu bar app and widget

```bash
pynids app
```

This builds the native app with the Command Line Tools, installs it to `~/Applications`,
and launches it. A shield appears in your menu bar.

**To add the widget:** right-click an empty spot on the desktop → **Edit Widgets…** → search
**PyNIDS** → pick small, medium, or large → drag it onto the desktop → **Done**.

To start the menu bar app at login: click the shield → ⚙︎ → **Launch at login**.

### 6. Enable "Explain with Claude" (optional)

1. Create an API key at [console.anthropic.com](https://console.anthropic.com) → **Settings → API Keys**, and add credit under **Billing**.
2. Save it for the daemon:

   ```bash
   sudo .venv/bin/pynids ai set-key
   ```

   Paste the key and press Enter. Nothing appears while you paste; that is intentional.

The key is stored at `/Library/Application Support/PyNIDS/anthropic-key` (mode 0600),
outside the project folder, so it is never committed to git.

### 7. Check everything is working

```bash
pynids status          # State should read "running on en0 + lo0"
pynids daemon logs -n 30
```

---

## 🧭 Everyday use

### Dashboard: `pynids open`

| Section | What it shows |
|---|---|
| **Overview** | Hidden events, threats, trackers, leaks and probes, encrypted DNS, countries reached; live throughput; events per minute over the last hour |
| **Network** | World map of every remote endpoint, sized by traffic. Orange dots raised an alert. Click one to see its events |
| **Apps** | Each app's upload and download, how many endpoints it talks to, its alerts, and which hosts and countries |
| **Events** | Live stream you can filter by kind, severity, and time range, with full-text search. Click an event to see its evidence, app, location, network owner, **Explain with Claude**, and **Block IP** |
| **Protection** | Blocked IPs (one-click unblock) and the status of each threat-intel feed |

### Menu bar

The shield's colour shows the threat level: green is all clear, yellow is notable, orange
is high severity, red is critical. The number next to it counts **high-severity alerts in
the last hour**. Click it for stats, throughput, recent alerts (hover one to block its IP),
busiest apps, pause/resume notifications (🔔), and **Open Dashboard** (⌘D).

### Widget

* **Headline.** "All clear", or how many notable (Medium or higher) alerts arrived in the last hour.
* **This session.** Trackers, leaks and probes, encrypted DNS sessions, countries reached.
* **Large size.** The latest alerts that need attention, and the busiest apps.
* It refreshes every few minutes (macOS decides exactly when). The menu bar app nudges it whenever new events arrive, and the "Updated" time shows how fresh it is. Click it to open the dashboard.

### Notifications

HIGH and CRITICAL alerts show as macOS banners, grouped into one banner if several arrive
together. Pause them from the menu bar or the dashboard's 🔔 button. Change the threshold in
the [config](#-configuration).

### Terminal X-Ray (no daemon needed)

```bash
sudo .venv/bin/pynids xray --iface en0
```

A full-screen live view of WebRTC leaks, localhost probes, QUIC endpoints, WebSockets,
trackers, and a rolling event stream, each tagged with its app.

---

## 🔄 Updating & restarting

After pulling new code, or whenever you want to be sure everything is current:

```bash
cd ~/NIDS
source .venv/bin/activate
git pull                                   # if updating from GitHub
pip install -e ".[all]"                    # picks up new dependencies
sudo .venv/bin/pynids daemon restart       # loads the new detection code
pynids app                                 # rebuilds the menu bar app + widget
```

Check it worked:

```bash
pynids status
curl -s http://127.0.0.1:8787/api/health   # shows the running version
```

To force the widget to refresh right away: `killall NotificationCenter`.

Config changes (see [Configuration](#-configuration)) also only need
`sudo .venv/bin/pynids daemon restart`.

---

## 🔎 Understanding the alerts

### Severity

| Level | Meaning | Notifies? |
|---|---|---|
| **Low** | Informational privacy telemetry: a tracker, a QUIC connection, a WebSocket | No |
| **Medium** | Worth knowing: encrypted DNS bypassing your resolver, a large upload, a LAN probe | No |
| **High** | Look at it: WebRTC leaking your private IP, a webpage probing localhost, a port scan, threat-intel hits | Yes |
| **Critical** | Act now: a localhost port scan by a webpage, a known botnet C2, a multi-vector attack | Yes (with sound) |

### Kinds

`threat` (threat-intel match) · `attack` (signatures, anomalies, behavioural) · `webrtc` ·
`localhost` · `doh` (encrypted DNS) · `tracker` · `beacon` · `websocket` · `quic` · `prefetch`

### X-Ray rule IDs

| Rule ID | What triggered it |
|---|---|
| `STEALTH-WEBRTC-LEAK` | STUN response leaked a private/loopback IP (HIGH) |
| `STEALTH-WEBRTC-REFLEXIVE` | STUN response revealed your public address (LOW) |
| `STEALTH-WEBRTC-STUN` / `-TURN` | WebRTC connectivity check or relay request (LOW) |
| `STEALTH-LOCALHOST-PROBE` | A browser connected to `127.0.0.0/8` or a LAN address on an unusual port |
| `STEALTH-LOCALHOST-SCAN` | One app probed 5+ local ports within 30 s. CRITICAL for browsers, HIGH for other apps |
| `STEALTH-QUIC-INITIAL` | First HTTP/3 connection to a site (with its hostname) |
| `STEALTH-WEBSOCKET` | WebSocket upgrade handshake |
| `STEALTH-BEACON` | `navigator.sendBeacon` POST or 1×1 tracking pixel |
| `STEALTH-DNS-PREFETCH` | Burst of third-party DNS lookups (`<link rel="dns-prefetch">`) |
| `STEALTH-TRACKER` | Connection to a tracker domain (TLS/QUIC SNI, HTTP Host, or DNS) |
| `STEALTH-ENCRYPTED-DNS` | DoH / DoT / DoQ session bypassing the system resolver |

### Built to stay quiet on a normal Mac

These detectors were tuned against real traffic so everyday use doesn't raise alarms:

* **Traffic spikes** only count traffic you *didn't* ask for (not your downloads), and only above 100 packets/s.
* **Port scans** count new connection attempts only, so replies (like your router's DNS answers) don't count. Local app-to-app traffic on loopback is ignored, and browsing many HTTPS sites isn't a "host sweep".
* **Large uploads** count bytes *you send*, from 100 MiB per connection. Video and voice calls through WebRTC relays are excluded.
* **Beaconing** ignores service discovery (mDNS, SSDP, broadcasts), time sync, and DNS.
* **Localhost probes** from ordinary apps talking to their own helpers aren't reported one by one; a scan is still caught, per app.
* **Correlation** ignores privacy telemetry, so your own browsing never makes your Mac look like an "attacker".
* **QUIC** is reported once per site, not once per CDN server.

If something is still noisy on your network, silence it with a suppression rule (see
[Configuration](#-configuration)).

---

## 🧠 How it works

```
 en0 (Wi-Fi/Ethernet) ─┐
 lo0 (loopback) ───────┴─► capture ─► dissect ─► enrich ─► flow tracking ─► detect ─► alert manager
                                     │          │                           │         (dedup, suppress,
                                     │          │                           │          correlate)
                     HTTP · DNS · TLS · QUIC    │               16 detectors +            │
                     STUN · SSH · SMTP          │               threat intel              ▼
                     (QUIC decrypt, TLS         │                                SQLite · live state ·
                      reassembly)        app · hostname ·                        notifications · auto-block
                                         country · ASN                                    │
                                                                                          ▼
                                                              local API (127.0.0.1:8787) ─► dashboard ·
                                                                                            menu bar · widget
```

* **Background service.** A launchd daemon running as root (`/Library/LaunchDaemons/com.pynids.daemon.plist`). It restarts itself on crashes and on network changes.
* **Storage.** Alerts go to SQLite with full-text search at `/Library/Application Support/PyNIDS/events.db`.
* **Threat intel.** Hash-indexed, so a lookup takes about 4 µs regardless of feed size. Feeds:

  | Feed | Source | Used for |
  |---|---|---|
  | `feodo` | abuse.ch Feodo Tracker | botnet C2 IPs (CRITICAL) |
  | `spamhaus_drop_v4` / `_v6` | Spamhaus DROP | hijacked / criminal netblocks (HIGH) |
  | `tor_exits` | Tor Project | Tor exit relays (LOW) |
  | `urlhaus` | abuse.ch URLhaus | malware-distribution hosts (HIGH) |
  | `disconnect` | Disconnect.me | 4,000+ tracker domains |
  | `doh_domains` / `doh_ipv4` | dibdot DoH lists | encrypted-DNS resolvers |

See [`documentation.md`](documentation.md) for the full technical reference.

---

## 🛑 Blocking, Claude & decryption

### Blocking with pf

```bash
pynids block add 203.0.113.50 --ttl 3600   # block for 1 hour (0 = forever)
pynids block list
pynids block remove 203.0.113.50
```

You can also block from any event in the dashboard, or by hovering a high-severity alert in
the menu bar.

* Blocks live in the pf sub-anchor `com.apple/250.PyNIDS`, which macOS's stock `pf.conf` already loads. No system file is edited.
* Blocks **expire automatically**. `sudo .venv/bin/pynids daemon uninstall` lifts them all.
* **Never blocked:** private, loopback, link-local, and multicast addresses, your router, and your DNS servers.
* **Auto-block** (off by default, `response.auto_block: true`) acts only on threat-intel matches and correlated multi-vector attacks at CRITICAL, never on privacy events. There's a `dry_run` mode to try it safely.

### Explain with Claude

After `sudo .venv/bin/pynids ai set-key`, click **Explain with Claude** on any event, or run:

```bash
pynids ai explain <alert-id>
```

Only that one alert is sent to Claude Opus 5, with its evidence and context, and only when
you click. You get back:

* **Verdict:** Benign, Privacy concern, Suspicious, or Malicious
* **What happened**, **Why it matters**, and **What to do**

Explanations are cached, so asking again costs nothing. Each new explanation costs about a cent.

### Seeing inside HTTPS

```bash
pynids keylog --browser chrome                 # opens a separate Chrome profile that logs TLS keys
sudo .venv/bin/pynids daemon install --record  # keeps a rolling ~500 MB window of raw traffic
pynids decrypt                                 # lists decrypted HTTPS / HTTP-2 / HTTP-3 requests
pynids decrypt --wireshark                     # opens the latest capture in Wireshark, keys loaded
```

Works with Chrome, Brave, Edge, and Firefox (Safari doesn't support key logging). Anyone
holding the key log can decrypt that browser's traffic, so it is created readable only by
you. Delete it when you're done. Needs `tshark` (`brew install --cask wireshark`).

---

## 🔧 Configuration

The daemon reads `/Library/Application Support/PyNIDS/config.yaml`, which is created on
install and fully commented (the template is
[`pynids/service/default_config.yaml`](pynids/service/default_config.yaml)). After editing,
run `sudo .venv/bin/pynids daemon restart`.

```yaml
daemon:
  interface: auto          # follow the default route, or e.g. "en0"
  loopback: true           # watch lo0 for webpages probing localhost
  api_port: 8787
  record_pcap: false       # rolling capture for `pynids decrypt`

notifications:
  enabled: true
  min_severity: HIGH       # LOW | MEDIUM | HIGH | CRITICAL
  min_interval: 15         # seconds; bursts become one banner

response:
  auto_block: false
  dry_run: false
  min_severity: CRITICAL
  ttl: 3600
  never_block: []          # extra IPs/CIDRs to protect

alert_manager:
  dedup_window: 60
  suppression:             # silence something that is noisy on your network
    - rule_id: STEALTH-QUIC-INITIAL
      src_cidr: 0.0.0.0/0

anomaly:
  min_rate_pps: 100        # never flag traffic spikes below this rate
behavioral:
  exfil_threshold_bytes: 104857600   # 100 MiB uploaded by one connection
```

The foreground CLI tools (`live`, `xray`, `pcap`) take `--config`. See
[`configs/enterprise.yaml`](configs/enterprise.yaml) for every engine setting.

---

## 📖 Command reference

| Command | What it does |
|---|---|
| `sudo pynids daemon install [--rules FILE] [--record]` | Install and start the background service |
| `sudo pynids daemon restart` | Apply code or config changes |
| `sudo pynids daemon uninstall` | Stop and remove the service, lifting all blocks |
| `pynids daemon logs [-f] [-n N]` | Show / follow the daemon log |
| `pynids status` | Health, threat level, traffic, apps, latest alert |
| `pynids open` | Open the web dashboard |
| `pynids app` | Build and install the menu bar app + widget |
| `pynids intel update` / `status` | Refresh / inspect threat-intel feeds |
| `sudo pynids geoip download` | Download the GeoIP databases |
| `pynids geoip lookup IP` | Look up one address |
| `pynids block add/remove/list/flush` | Manage pf blocks |
| `sudo pynids ai set-key` | Store your Anthropic API key |
| `pynids ai explain ALERT_ID` | Explain an alert with Claude |
| `pynids keylog [--browser …]` | Launch a browser that logs TLS keys |
| `pynids decrypt [PCAP…] [--wireshark]` | List decrypted requests from recorded traffic |
| `sudo pynids xray --iface en0` | Live terminal X-Ray dashboard |
| `sudo pynids live --iface en0 [--rules FILE]` | Classic IDS output to the terminal |
| `pynids pcap --file capture.pcap` | Analyse a capture file |
| `pynids query --db FILE` / `pynids stats --db FILE` | Search / summarise a SQLite alert database |
| `pynids validate FILE` | Check a rules or config file |

Every command has `--help`. Use `.venv/bin/pynids` with `sudo`.

<details>
<summary><b>More detail on <code>live</code>, <code>xray</code>, <code>pcap</code>, <code>query</code></b></summary>

```bash
sudo .venv/bin/pynids live \
  --iface en0 \
  --rules rules/enterprise_rules.yaml \
  --config configs/enterprise.yaml \
  --bpf "not port 22" \
  --sqlite alerts.db \
  --output text \            # text | json
  --min-severity MEDIUM \
  --verbose

sudo .venv/bin/pynids xray --iface en0 --json-log xray.jsonl
sudo .venv/bin/pynids xray --iface eth0 --loopback-iface lo      # Linux

pynids pcap --file capture.pcap --rules rules/enterprise_rules.yaml --output json \
  | jq 'select(.severity=="CRITICAL")'

sudo .venv/bin/pynids query --db "/Library/Application Support/PyNIDS/events.db" --min-severity HIGH
```

</details>

---

## 🔐 Privacy & security

* **Everything stays on your Mac.** The only outbound requests are feed and GeoIP downloads and, only when you click it, Explain with Claude.
* **The API listens on `127.0.0.1` only**, and a malicious webpage can't use it:
  * a **Host-header allowlist** blocks DNS-rebinding attacks
  * a **random token** is required for every data route
  * an **Origin check** protects every action that changes something
  * **no CORS headers** are sent, so other origins can't read responses
* **`/api/widget`** is the only open route, because the sandboxed widget can't read the token. It returns counts and alert headlines only.
* **Secrets live outside the repo**, in `/Library/Application Support/PyNIDS/`, and `.gitignore` also blocks keys, key logs, captures, and databases.

### Files on disk

| Path | Contents |
|---|---|
| `/Library/LaunchDaemons/com.pynids.daemon.plist` | Background service definition |
| `/Library/Application Support/PyNIDS/config.yaml` | Your settings |
| `…/events.db` | Alert history |
| `…/intel/`, `…/geoip/` | Cached feeds, GeoIP databases |
| `…/api-token`, `…/anthropic-key` | API token (0644), Claude key (0600) |
| `…/blocklist.json` | Active blocks and why |
| `…/captures/` | Rolling capture (only with `--record`) |
| `/Library/Logs/PyNIDS/daemon.log` | Daemon log |
| `~/Applications/PyNIDS.app` | Menu bar app + widget |

---

## 🩺 Troubleshooting

| Problem | Fix |
|---|---|
| `pip install -e .` fails with *"setup.py not found … editable mode"* | Old pip. Run `pip install --upgrade pip`, then install again |
| `sudo: pynids: command not found` | `sudo` doesn't see the venv. Use `sudo .venv/bin/pynids …` |
| Dashboard says **"Capture needs root"** | The daemon isn't running as root. Run `sudo .venv/bin/pynids daemon install` |
| `pynids status` says **not running** | Check `pynids daemon logs -n 50`, then `sudo .venv/bin/pynids daemon restart` |
| **Widget not in the gallery** | Run `pynids app` again, open the app once, then `killall NotificationCenter` and reopen **Edit Widgets** |
| Widget shows **"Not running"** | The daemon is down. See above |
| Widget numbers look stale | It refreshes every few minutes. Check the "Updated" time, or run `killall NotificationCenter` |
| World map is empty | Run `sudo .venv/bin/pynids geoip download` and restart. The map outline also needs internet access |
| Many **"Unattributed"** connections | Very short-lived connections can close before they're matched. Run `sudo .venv/bin/pynids daemon restart` to make sure the latest attribution code is loaded |
| **Explain with Claude** errors | Invalid key → `sudo .venv/bin/pynids ai set-key`. Rate limit → wait a minute. Also check your credit balance |
| Too many alerts of one kind | Add a suppression rule (see [Configuration](#-configuration)) or raise `notifications.min_severity` |
| `git commit` says *"Author identity unknown"* | `git config --global user.name "…"` and `git config --global user.email "…"` |

---

## 🧹 Uninstall

```bash
sudo .venv/bin/pynids daemon uninstall                 # stops the service, lifts all blocks
rm -rf ~/Applications/PyNIDS.app                        # menu bar app + widget
sudo rm -rf "/Library/Application Support/PyNIDS" /Library/Logs/PyNIDS   # data, keys, logs
```

---

## 🧪 For developers

### Tests

```bash
pip install -e ".[dev,all]"
pytest                                    # 201 tests
pytest --cov=pynids --cov-report=term-missing
```

Tests use real protocol test vectors (for example the RFC 9001 QUIC keys) and cover every
detector, the false-positive regressions above, the API security checks, pf guard rails,
and the Claude request shape.

### Project layout

```
pynids/
├── engine.py            detection pipeline
├── sniffer.py           live capture / PCAP replay
├── protocols/           HTTP, DNS, TLS, QUIC (+ decryption), STUN, SSH, SMTP
├── detection/           signature, anomaly, behavioural, X-Ray (stealth) detectors
├── enrich/              app attribution (psutil + nettop), hostnames, GeoIP
├── intel/               threat intel index + live feeds
├── alerts/              alert model, manager, outputs (SQLite, JSON, syslog, terminal)
├── response/            pf blocking, macOS notifications
├── ai/                  Explain with Claude
├── service/             daemon, local API, live stats, launchd, PCAP recorder
├── web/dashboard.html   web dashboard
├── cli.py, cli_service.py
macos/
├── src/                 SwiftUI menu bar app + WidgetKit widget
├── build.sh             builds both with the Command Line Tools only
└── swiftbar/            alternative SwiftBar menu bar plugin
configs/  rules/  intel/  tests/
```

### Writing signature rules

```yaml
rules:
  - id: "SIG-EXP-001"
    description: "SQL injection pattern in HTTP URI"
    severity: CRITICAL          # LOW | MEDIUM | HIGH | CRITICAL
    confidence: 0.88
    mitre: "T1190"
    tags: [sqli, webapp]
    match:
      all:
        - {field: protocol, op: eq, value: tcp}
        - {field: dst_port, op: in, value: [80, 8080]}
        - {field: layer7.http.sqli_suspect, op: eq, value: true}
    threshold: {count: 3, seconds: 60}   # optional
```

**Operators:** `eq`, `ne`, `lt`, `gt`, `lte`, `gte`, `in`, `not_in`, `contains`,
`startswith`, `regex`, `exists`. Combine conditions with `all` / `any` / `not`.

**Fields** include `src_ip`, `dst_ip`, `dst_port`, `protocol`, `layer7.http.uri`,
`layer7.http.user_agent`, `layer7.dns.query_name`, `layer7.dns.answers`, `layer7.tls.sni`,
`layer7.tls.alpn`, `layer7.tls.ja3`, `layer7.tls.ech`, `layer7.quic.sni`, and
`layer7.ssh.software`.

Validate rules with `pynids validate rules/my_rules.yaml`. Rules hot-reload in `live` mode.

### Embedding the engine

```python
from pynids.engine import DetectionEngine
from pynids.alerts.manager import AlertManager
from pynids.alerts.outputs.json_file import JsonFileOutput
from pynids.enrich import Enricher, HostnameCache, ProcessResolver

mgr = AlertManager(dedup_window=60)
mgr.register_output(JsonFileOutput("alerts.json"))
engine = DetectionEngine(
    config={}, rules_path="rules/enterprise_rules.yaml", alert_manager=mgr,
    enricher=Enricher(processes=ProcessResolver().start(), hostnames=HostnameCache()),
)
alerts = engine.process_packet(meta)   # meta from pynids.sniffer.packet_to_meta()
```

### MITRE ATT&CK coverage

| Technique | ID | Detector |
|---|---|---|
| Active Scanning | T1595 | Signature (scanner user agents) |
| Network Service Discovery | T1046 | `PortScanDetector`, `LocalhostProbeDetector` |
| Brute Force | T1110 | `BruteForceDetector` |
| Exploit Public-Facing Application | T1190 | Signatures + `HttpAttackDetector` |
| Command & Scripting Interpreter | T1059.* | Signatures (reverse shells, PowerShell, Python) |
| Application Layer Protocol: DNS | T1071.004 | `DnsTunnelingDetector`, `DohDetector` |
| Application Layer Protocol: Web | T1071.001 | Signatures, X-Ray detectors |
| Application Layer Protocol (C2) | T1071 | `BeaconingDetector`, threat intel |
| Exfiltration Over C2 Channel | T1041 | `DataExfiltrationDetector` |
| Exfiltration Over Alternative Protocol | T1048.003 | Signature (DNS TXT) |
| Remote Services (SMB / RDP) | T1021.* | Signatures |
| Network Denial of Service | T1498 | `AnomalyDetector` |
| Gather Victim Host Information | T1592.004 | `WebRtcLeakDetector` |

---

## 📄 License

MIT License. See `pyproject.toml`.

**Credits:** IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0) · tracker list by
[Disconnect](https://disconnect.me/trackerprotection) (CC BY-NC-SA 4.0) · threat feeds by
[abuse.ch](https://abuse.ch), [Spamhaus](https://www.spamhaus.org/drop/), and the
[Tor Project](https://www.torproject.org) · packet capture by [Scapy](https://scapy.net).
