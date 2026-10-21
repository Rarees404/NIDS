<div align="center">

# 🛡️ PyNIDS

### Network intrusion detection, privacy X-Ray, and a SOC analyst toolkit for your Mac

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#-license)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/tests-372%20passing-brightgreen.svg)]()

PyNIDS watches your Mac's real network traffic and tells you, in plain language, what is
going on. It catches attacks and connections to known-malicious servers. It also shows
what browsers and apps do quietly behind your back: trackers, WebRTC IP leaks, webpages
port-scanning your machine, DNS hidden inside HTTPS, and more. For every connection you see
**which app** made it and **where in the world** it went.

Every alert comes with a **plain-English explanation**: what happened, whether it is
usually harmless, and what to do. It runs as an always-on background service, with a
**web dashboard**, a **menu bar app** (stop, resume, or quit from there), a **desktop
widget**, **native notifications**, one-click **blocking**, and optional
**"Explain with Claude"** for a deeper look at any alert.

For analysts, it adds an **investigation workbench** and a **forensic email analyser**.
Look up any IP, domain, URL or hash across a dozen threat-intel sources and pivot through
the results. Take a phishing email apart safely, where every finding points to the exact
raw lines it is based on. A **Thunderbird add-on** sends messages in one click.

</div>

---

## Contents

0. [Quick start](#-quick-start)
1. [What you get](#-what-you-get)
2. [Requirements](#-requirements)
3. [Installation (step by step)](#-installation-step-by-step)
4. [Everyday use](#-everyday-use)
5. [Updating & restarting](#-updating--restarting)
6. [Understanding the alerts](#-understanding-the-alerts)
7. [How it works](#-how-it-works)
8. [Blocking, Claude & decryption](#-blocking-claude--decryption)
9. [SOC analyst tools: Investigate & Email](#-soc-analyst-tools-investigate--email)
10. [Configuration](#-configuration)
11. [Command reference](#-command-reference)
12. [Privacy & security](#-privacy--security)
13. [Troubleshooting](#-troubleshooting)
14. [Uninstall](#-uninstall)
15. [For developers](#-for-developers)

---

## ⚡ Quick start

Already have Python 3.9+ and git? These five commands get you a running PyNIDS:

```bash
git clone https://github.com/Rarees404/NIDS.git ~/NIDS && cd ~/NIDS
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -e ".[all]"
sudo .venv/bin/pynids daemon install      # background service (asks for your password)
pynids open                               # dashboard at http://127.0.0.1:8787
```

Then open the **Investigate** or **Email** tab in the dashboard's top bar. The full
walkthrough, with what each step does and how to check it worked, is in
[Installation](#-installation-step-by-step).

---

## ✨ What you get

### Detection

| | |
|---|---|
| **Attacks & anomalies** | Port scans and host sweeps, brute force (SSH, RDP, VNC, mail …), SQL injection / XSS / path traversal, DNS tunnelling, C2 beaconing, large uploads, unsolicited traffic floods, and 20+ MITRE-tagged signature rules |
| **Live threat intelligence** | Every IP, DNS name, and TLS/QUIC hostname is checked against abuse.ch Feodo (botnet C2) and URLhaus (malware), Spamhaus DROP, and Tor exit lists, refreshed every 6 hours |
| **Correlation** | Several different attack signatures from one source become a single CRITICAL "multi-vector attack" alert |
| **Untrusted programs** | Every program that reaches the internet has its code signature checked (Apple, App Store, Developer ID, ad-hoc, unsigned, or tampered) and its location judged (`/tmp`, hidden folders, `/Users/Shared`, Downloads …). Homebrew, pip, npm and other dev-tool locations are recognised, so ordinary developer tools stay quiet |
| **Likely command-and-control** | One CRITICAL alert when independent signals line up for the same program and server: regular check-ins, a bare IP never looked up in DNS, a blocklist hit, an untrusted binary, a brand-new program, or a server Shodan tags as C2 |
| **Baseline** | Learns this Mac for a day, then flags change: a program using the network for the first time, or an app suddenly talking to a new country (browsers excluded) |
| **Persistence** | Every LaunchAgent / LaunchDaemon is listed with the program it starts and that program's signature; untrusted programs are linked to the launch item that keeps restarting them |
| **Your network** | Devices on your LAN (from the neighbour table, named via mDNS), with an alert when a new one joins and optional `nmap` identification |

### Privacy X-Ray: what DevTools doesn't show you

| | |
|---|---|
| **WebRTC IP leaks** | STUN responses that reveal your private or public IP, even behind a VPN |
| **Localhost probing** | Webpages port-scanning `127.0.0.1` or your LAN to fingerprint installed software |
| **Trackers** | 4,000+ ad, analytics, fingerprinting, and crypto-mining domains (Disconnect list) |
| **Encrypted DNS** | DNS-over-HTTPS / TLS / QUIC sessions that bypass your system resolver |
| **QUIC / HTTP-3, WebSockets, beacons, prefetch storms** | Background connections that never show up in the browser's Network tab |

### Fast, accurate capture

* **Raw-frame decoder.** Packets are read straight from the kernel's BPF socket and decoded with a small built-in parser (Ethernet, VLAN, loopback/`utun`, IPv4/IPv6, TCP/UDP/ICMP). About 23 µs per packet end to end, roughly 44,000 packets/s per core, 8× faster than before.
* **Every DNS packet is seen.** Scapy used to swallow DNS and mDNS into its own layers, so DNS-based detection, tracker matching, and hostname learning missed live traffic. They now see all of it.

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
| **Web dashboard** | `http://127.0.0.1:8787`: a "needs your attention" summary, every live connection and the program behind it, what's exposed, a grouped event stream, per-app traffic, a world map, LAN devices, launch items, blocking, and Ask Claude. Works offline: nothing is loaded from a CDN |
| **Menu bar app** | Shield icon that changes colour with the threat level; popover with stats, a throughput graph, recent alerts, and busiest apps |
| **Desktop widget** | Small / medium / large. Headlines what needs attention *in the last hour*, or "All clear" |
| **Notifications** | macOS banners for HIGH and CRITICAL alerts; bursts are grouped into one banner |
| **Terminal** | `pynids status`, and the live full-screen `pynids xray` dashboard |

### Plain-English alerts

Every alert carries a short guide, written from that alert's own evidence (which app, which host, how often):

* **Summary.** *"Microsoft Outlook contacts outlook.office365.com every 16 minutes, very regularly."*
* **Verdict.** `Usually harmless` · `Privacy` · `Worth checking` · `Act now`
* **What it means** and **what to do next**, with concrete commands where useful.

It's generated locally and instantly, with no network calls. The dashboard, menu bar, widget, and notifications all show it.

### SOC analyst toolkit

| | |
|---|---|
| **Investigate** | One search box for IPs, domains, URLs, file hashes, email addresses, ASNs and CVEs (defanged input welcome). Up to 13 sources answer in parallel: VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, urlscan.io, URLhaus, ThreatFox, MalwareBazaar, Shodan InternetDB, RDAP/WHOIS, DNS, Certificate Transparency, and what *this Mac* saw. Each source shows a verdict, a summary, pivots, and its untouched raw response |
| **Bulk extraction** | Paste a whole alert, ticket or threat report. Every indicator is extracted, de-duplicated, and ready to copy defanged, export as CSV, or investigate |
| **Pivoting** | Click any value in any result (resolved IP, name server, payload hash, certificate name) to investigate it. Your pivot trail stays visible |
| **Email forensics** | Drop an `.eml`, paste raw source, or send from Thunderbird. The original is stored unchanged and identified by its SHA-256. A lossless MIME parser decodes every part and records the raw lines behind each header, part and finding |
| **Phishing checks** | SPF/DKIM/DMARC and alignment, a display name hiding another address, Reply-To mismatches, look-alike and punycode domains, link text that lies about the target (SafeLinks/Proofpoint unwrapped), hidden HTML, forms, tracking pixels, invisible characters |
| **Attachment triage** | Real file type vs. extension, double extensions, right-to-left-override names, macros, encrypted archives (with contents), PDF active content, RTF exploits, HTML smuggling, plus hashes, hex and strings. Nothing is ever executed |
| **Raw viewer** | The exact message source with colour-coded header groups, MIME boundaries, hidden zones, folded base64, clickable indicators, and invisible characters made visible |
| **Integrations** | Thunderbird add-on ("Analyze in PyNIDS"), VS Code `.eml` highlighting, and `pynids investigate` / `pynids mail analyze` in the terminal |

### Response

* **Blocking** through macOS's built-in `pf` firewall, from the dashboard, menu bar, or CLI. Optionally automatic for confirmed threats, with guard rails and expiry.
* **Explain with Claude.** One click sends a single alert to Claude, together with what PyNIDS knows about the program and server, for a deeper, case-specific analysis.
* **Ask Claude.** Ask a question ("is anything on my Mac suspicious right now?") and Claude investigates with read-only tools: connections, programs, signatures, launch items, alerts, IP lookups.
* **Mark as expected.** Silence an app + host, a kind of alert for one app, or a rule, straight from the alert. Undo any time under Protection.
* **IP dossier.** Click any IP for everything PyNIDS saw plus reverse DNS, RDAP (owner, abuse contact) and Shodan InternetDB (open ports, tags, CVEs).
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

Open **Terminal** (Applications → Utilities → Terminal) and follow the steps in order.
Lines starting with `#` are comments; you don't type them.

### 0. Check the prerequisites

```bash
python3 --version        # needs 3.9 or newer
git --version            # if macOS offers to install the developer tools, accept
xcode-select -p          # prints a path if the Command Line Tools are installed
```

If `xcode-select -p` prints an error, run `xcode-select --install` and wait for the
installer to finish. It provides `git`, and the compiler for the menu bar app.

### 1. Get the code and install it

```bash
git clone https://github.com/Rarees404/NIDS.git ~/NIDS   # download the project
cd ~/NIDS                                                # go into it

python3 -m venv .venv          # create a private Python environment in ~/NIDS/.venv
source .venv/bin/activate      # use it in this Terminal window (your prompt shows "(.venv)")
pip install --upgrade pip      # macOS ships an old pip that can't install this project
pip install -e ".[all]"        # PyNIDS + GeoIP + Claude support
```

Check it worked: `pynids --help` lists the commands.

> **Every new Terminal window** needs `cd ~/NIDS && source .venv/bin/activate` before
> plain `pynids …` commands work. With `sudo`, always use the full path
> `sudo .venv/bin/pynids …` instead.

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
pynids status                               # State should read "running on en0 + lo0"
curl -s http://127.0.0.1:8787/api/health    # {"ok": true, "version": "…"}
pynids daemon logs -n 30                    # the last lines of the service log
```

### 8. Set up the SOC tools (optional)

The **Investigate** and **Email** tabs work straight away. These extras make them stronger.

**Free API keys for more intel sources.** In the dashboard open **Investigate → Sources & API keys**,
paste a key, and press **Save**. Keys are stored only on this Mac.

| Source | Where to get a free key | Free limit |
|---|---|---|
| VirusTotal | [virustotal.com](https://www.virustotal.com) → sign up → your profile → **API key** | 4 lookups/min, 500/day |
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) → Account → **API** | 1,000 checks/day |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) → Settings → **OTX Key** | generous |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar) | [auth.abuse.ch](https://auth.abuse.ch/) → one **Auth-Key** for all three | generous |
| GreyNoise *(works without a key)* | [viz.greynoise.io/signup](https://viz.greynoise.io/signup) | higher limit with a key |
| urlscan.io *(works without a key)* | [urlscan.io/user/signup](https://urlscan.io/user/signup) | higher limit with a key |

**Thunderbird add-on.**

```bash
pynids mail thunderbird     # writes ~/Downloads/pynids-thunderbird.xpi
pynids mail token           # prints the token the add-on needs (copy it)
```

1. In Thunderbird: **☰ → Add-ons and Themes → ⚙ (gear) → Install Add-on From File…** and pick
   `~/Downloads/pynids-thunderbird.xpi`. Accept the permissions.
2. On the add-on's card choose **Options** (or **Preferences**), paste the token, leave the port
   at `8787`, press **Save**, then **Test connection**. It should say *Connected ✓*.
3. Open any message and click **Analyze in PyNIDS** in the message header toolbar, or
   right-click one or more messages in the list. The analysis opens in your browser.

**VS Code highlighting for raw emails.**

```bash
pynids mail vscode          # installs into ~/.vscode/extensions
```

Restart VS Code and open any `.eml` file. Headers are coloured by group (routing,
authentication, identity, MIME), with boundaries, encoded words, base64 blocks, links, IPs,
addresses and invisible characters highlighted. Boundaries are foldable.

### Running without the background service

The daemon is only needed for live monitoring. The analyst tools also work without it:

```bash
pynids mail analyze suspicious.eml --local      # full phishing analysis in the terminal
sudo .venv/bin/pynids xray --iface en0          # live X-Ray view, stops when you press Ctrl-C
pynids pcap --file capture.pcap                 # analyse a capture file
```

`pynids investigate` and the dashboard tabs do need the daemon running.

---

## 🧭 Everyday use

### Dashboard: `pynids open`

| Tab | What it shows |
|---|---|
| **Overview** | **Needs your attention**: the few things worth a look right now (serious alerts from the last hour, untrusted programs, exposed ports, new devices), or "All clear". **Ask Claude**. Then the counters, live throughput, events per minute, and events by kind |
| **Connections** | Every program with an open socket, riskiest first, with its signature and flags; every live connection (app, remote host, country, network owner, signature, alerts), filterable by Internet / Flagged / All; and **What's exposed**: listening ports and who can reach them. Click a program for its verified signature, SHA-256 (with a VirusTotal link), the launch items that start it, and its sockets |
| **Events** | Live stream you can filter by kind, severity, and time range, with full-text search. Similar events are grouped (×N). Click one to see **What this means** and what to do, the app and program, **Explain with Claude**, **Block IP**, and **Mark as expected** |
| **Apps** | Each app's upload and download, endpoints, alerts, hosts and countries. Click an app for its hosts, countries, remote IPs and learned "usual countries" |
| **Network** | World map of every remote endpoint (click a dot for its IP dossier) and the devices on your LAN, with optional nmap scans |
| **Protection** | Blocked IPs, rules you marked as expected, launch items, and threat-intel feed status |
| **Investigate** | The analyst workbench: look up and pivot on any indicator (see below) |
| **Email** | Forensic analysis of suspicious emails (see below) |

Every IP address anywhere in the dashboard is clickable and opens its dossier. The IP
dossier and every alert also have an **Investigate** button that opens the indicator in
the workbench.

### Investigating an indicator: a walkthrough

1. Open **Investigate**, or run `pynids investigate 185.220.101.4 --web`.
2. Type or paste the indicator and press **Enter**. Defanged input like `hxxps://evil[.]com/x`
   or `1.2.3[.]4` is fine. Paste a whole report to get a list of every indicator in it instead.
3. Cards appear as each source answers. The coloured bar on top of a card is that source's
   verdict. The banner at the top combines them, e.g. *Malicious* if any source says so.
4. Open **Raw response** on any card to see exactly what the source returned. The summary
   is always checkable against it.
5. Click any value under **Pivot** to investigate it next. Use the pivot trail at the top to go back.
6. **Copy report** puts a defanged Markdown summary on your clipboard for a ticket.
   **Block** (for public IPs) adds a firewall block. **Open in…** links to 30+ other tools.

Lookups are cached (most for 6 hours). The refresh icon on a card skips the cache.

### Analysing a phishing email: a walkthrough

1. **Get the original message**, not the text you see on screen:
   * **Thunderbird:** the **Analyze in PyNIDS** button (see [step 8](#8-set-up-the-soc-tools-optional)), or *More → Save As* an `.eml`
   * **Apple Mail:** *File → Save As…* → Format: **Raw Message Source**
   * **Outlook (Mac):** drag the message to the Desktop (creates an `.eml`)
   * **Gmail:** ⋮ → **Download message** (or **Show original** → copy)
2. Drop the file on the **Email** tab, paste the source, or run `pynids mail analyze file.eml --web`.
3. **Overview** lists the findings, most severe first. Every finding has a **lines N–M** button.
   Click it to see the proof highlighted in the raw source. Below that are the sender details,
   SPF/DKIM/DMARC, and the delivery path (Received hops, oldest first).
4. **Raw source** is the message exactly as received. The left side jumps to any header or MIME
   part. Search with the box. Click any URL, IP or address to investigate it.
5. **Links** shows every URL found anywhere in the message, with its flags and the text it was
   shown as. **Attachments** shows the real type, risks, hashes, hex and strings.
6. **Body → Render safely** shows the HTML in a sandbox with every remote request blocked, so
   the sender can't tell it was opened.
7. **Indicators → Investigate all** sends every IP, domain, URL and hash to the workbench.
   **Copy report** gives a defanged summary.

The original `.eml` stays downloadable, byte-for-byte, under **Original .eml**. Its SHA-256
is shown at the top so you can prove the evidence wasn't altered.

### Menu bar

The shield's colour shows the threat level: green is all clear, yellow is notable, orange
is high severity, red is critical. The number next to it counts **high-severity alerts in
the last hour**. Click it for stats, throughput, recent alerts (each with its summary and
verdict; hover for the full explanation, or to block its IP), busiest apps, pause/resume
notifications (🔔), and **Open Dashboard** (⌘D).

The **power menu** in the popover controls PyNIDS itself:

| Item | What it does |
|---|---|
| **Stop Detection** / **Resume Detection** | Stops capturing and analysing traffic without shutting the service down. The icon turns into a ⏸ and no alerts appear. The choice survives restarts and reboots until you resume |
| **Quit PyNIDS Completely…** | Asks for your password, shuts down the background daemon (it stays off after reboot), and quits the menu bar app |
| **Start PyNIDS…** | Shown when the daemon is shut down: starts it again |
| **Quit Menu Bar App Only** | Closes the menu bar app; monitoring continues in the background |

### Widget

* **Headline.** "All clear", or how many notable (Medium or higher) alerts arrived in the last hour.
* **This session.** Trackers, leaks and probes, encrypted DNS sessions, countries reached.
* **Large size.** The latest alerts that need attention, and the busiest apps.
* It refreshes every few minutes (macOS decides exactly when). The menu bar app nudges it whenever new events arrive, and the "Updated" time shows how fresh it is. Click it to open the dashboard.

### Notifications

HIGH and CRITICAL alerts show as macOS banners, grouped into one banner if several arrive
together. The banner text is the plain-English summary, and the subtitle shows the verdict
and the app. Pause them from the menu bar or the dashboard's 🔔 button. Change the threshold in
the [config](#-configuration).

### Terminal X-Ray (no daemon needed)

```bash
sudo .venv/bin/pynids xray --iface en0
```

A full-screen live view of WebRTC leaks, localhost probes, QUIC endpoints, WebSockets,
trackers, and a rolling event stream, each tagged with its app.

---

## 🔄 Updating & restarting

### One-click updates (no terminal)

PyNIDS checks GitHub for new commits every 6 hours. When there is one:

* the **dashboard** shows an **Update** button in the top bar (or use *Check for updates* in the footer), and
* the **menu bar app** shows *"PyNIDS x.y is available"* with an **Update** button (or ⚙︎ → **Check for Updates**).

Pressing **Update** downloads the new code, installs any new dependencies, checks that it
starts, and restarts PyNIDS (monitoring pauses for a few seconds). If the menu bar app
itself changed, it rebuilds and relaunches itself. If anything fails, the previous version
is restored and the error is shown. From a terminal: `pynids update`.

Updates are only applied as a fast-forward of your checkout. If you have local commits, or
unsaved edits to files the update changes, PyNIDS says so and leaves the folder alone.
Turn the periodic check off with `updates: {check: false}` in the [config](#-configuration).

> **Releasing:** bump `version` in `pyproject.toml` **and** `__version__` in
> `pynids/__init__.py` before pushing, so users see "PyNIDS 2.1.0 is available" rather
> than just "a new version".

### Manually

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

### Verdicts

Severity is how serious an event *could* be; the verdict is the plain-English call on this
particular event.

| Verdict | Meaning |
|---|---|
| **Usually harmless** | Normal behaviour for this app or this kind of event. Nothing to do unless it surprises you |
| **Privacy** | Not an attack, but something is tracking you or leaking information |
| **Worth checking** | Could be fine, could be a problem. The guide says what to look at |
| **Act now** | A known-malicious server or a clear attack. Follow the next steps |

### Kinds

`threat` (threat-intel match) · `attack` (signatures, anomalies, behavioural) · `webrtc` ·
`localhost` · `doh` (encrypted DNS) · `tracker` · `beacon` · `websocket` · `quic` · `prefetch` ·
`host` (programs & devices)

### X-Ray rule IDs

| Rule ID | What triggered it |
|---|---|
| `STEALTH-WEBRTC-LEAK` | STUN response leaked a private/loopback IP (HIGH) |
| `STEALTH-WEBRTC-REFLEXIVE` | STUN response revealed your public address (LOW) |
| `STEALTH-WEBRTC-STUN` / `-TURN` | WebRTC connectivity check or relay request (LOW) |
| `STEALTH-LOCALHOST-PROBE` | Something connected to `127.0.0.0/8` or a LAN address on an unusual port. HIGH from a browser, MEDIUM/LOW when the app couldn't be identified, silent for ordinary apps |
| `STEALTH-LOCALHOST-SCAN` | One app probed 5+ local ports within 30 s. CRITICAL for browsers, HIGH for other apps |
| `STEALTH-QUIC-INITIAL` | First HTTP/3 connection to a site (with its hostname) |
| `STEALTH-WEBSOCKET` | WebSocket upgrade handshake |
| `STEALTH-BEACON` | `navigator.sendBeacon` POST or 1×1 tracking pixel |
| `STEALTH-DNS-PREFETCH` | Burst of third-party DNS lookups (`<link rel="dns-prefetch">`) |
| `STEALTH-TRACKER` | Connection to a tracker domain (TLS/QUIC SNI, HTTP Host, or DNS) |
| `STEALTH-ENCRYPTED-DNS` | DoH / DoT / DoQ session bypassing the system resolver, or iCloud Private Relay in use (LOW) |

### Host rule IDs

| Rule ID | What triggered it |
|---|---|
| `HOST-PROCESS-RISK` | An untrusted program reached the internet: LOW when it is only unsigned outside a dev-tool location, MEDIUM when it runs from a suspicious place, HIGH when both, or when its signature is broken. Once per program |
| `HOST-NEW-PROGRAM` | A program used the internet for the first time after the 24 h learning period (MEDIUM if untrusted) |
| `BASELINE-NEW-COUNTRY` | A non-browser app contacted a country it never used before (LOW) |
| `LAN-NEW-DEVICE` | A new MAC address appeared on your local network (LOW) |
| `HOST-C2-LIKELY` | Two or more independent C2 signals for the same program and server, at least one of them network-side (CRITICAL) |

Other detectors worth knowing:

* **Brute force** counts new connection attempts only, not packets inside a session. Attempts *against your Mac* are HIGH ("Brute force on SSH"). Many connections *from your Mac* to one service are MEDIUM ("Many SSH connections"), since that's usually git over SSH or a mail client reconnecting.
* **Beaconing** (regular check-ins) is MEDIUM when the app polls a named server it looked up, and HIGH when it polls a **bare IP with no DNS lookup**, the more malware-like pattern.

### Built to stay quiet on a normal Mac

These detectors were tuned against real traffic so everyday use doesn't raise alarms:

* **Traffic spikes** only count traffic you *didn't* ask for (not your downloads), and only above 100 packets/s.
* **Port scans** count new connection attempts only, so replies (like your router's DNS answers) don't count. Local app-to-app traffic on loopback is ignored, and browsing many HTTPS sites isn't a "host sweep".
* **Large uploads** count bytes *you send*, from 100 MiB per connection. Video and voice calls through WebRTC relays are excluded.
* **Beaconing** only looks at new connections to public internet addresses. It ignores your LAN (AirPlay, printers, NAS), loopback, service discovery, time sync, DNS, and macOS system daemons running from SIP-protected paths (`/System`, `/usr/libexec`, `/usr/sbin`).
* **Brute force** ignores the packets of an ongoing SSH or mail session.
* **Localhost probes** from ordinary apps talking to their own helpers aren't reported one by one; a scan is still caught, per app. Local IPC (a program connecting to a socket it just opened), PyNIDS's own dashboard port, and broadcasts are ignored, and the same app → port probe is reported at most once an hour (the next alert says how many repeats were skipped).
* **iCloud Private Relay** is reported once, as LOW, not as a stream of encrypted-DNS alerts.
* **Correlation** ignores privacy telemetry, so your own browsing never makes your Mac look like an "attacker".
* **QUIC** is reported once per site, not once per CDN server.

If something is still noisy on your network, silence it with a suppression rule (see
[Configuration](#-configuration)).

---

## 🧠 How it works

```
 en0 (Wi-Fi/Ethernet) ─┐
 lo0 (loopback) ───────┴─► capture ──────► raw BPF frames, decoded in-house (no Scapy objects)
                              │
                              ▼
                           dissect ──────► HTTP · DNS · TLS · QUIC · STUN · SSH · SMTP
                              │            (QUIC decrypt, TLS reassembly)
                              ▼
                           enrich ───────► app · hostname · country · ASN
                              │
                              ▼
                     flow tracking + detect ► 16 detectors + threat intel
                              │
                              ▼
                        alert manager ───► dedup · suppress · correlate · plain-English guide
                              │
                              ▼
          SQLite · live state · notifications · auto-block
                              │
                              ▼
          local API (127.0.0.1:8787) ─► dashboard · menu bar · widget
```

* **Background service.** A launchd daemon running as root (`/Library/LaunchDaemons/com.pynids.daemon.plist`). It restarts itself on crashes and on network changes. Detection can be paused without stopping the service (`POST /api/detection`, used by the menu bar app).
* **Capture.** A reader thread drains the BPF socket (`AF_PACKET` on Linux) into a bounded queue; the engine thread decodes raw frames itself. If the engine falls behind, packets are dropped and counted rather than piling up in memory.
* **Alert guide.** [`pynids/alerts/guide.py`](pynids/alerts/guide.py) turns each alert into a summary, verdict, explanation, and next steps. The API attaches it as `about` on every alert.
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

Only that one alert is sent to Claude Opus 5.5, with its evidence and context, and only when
you click. PyNIDS adds what it knows about the program (signature, launch items) and the
server (owner and reputation lookups), so Claude can tell a signed vendor app talking to its
own cloud from an unsigned binary in `/tmp` calling a bare IP. You get back:

* **Verdict:** Benign, Privacy concern, Suspicious, or Malicious
* **What happened**, **Why it matters**, and **What to do**

Explanations are cached, so asking again costs nothing. Each new explanation costs about a cent.

### Ask Claude (investigation)

Type a question in **Ask Claude** on the Overview tab, or run:

```bash
pynids ai ask "is anything on my Mac suspicious right now?"
```

Claude answers by calling read-only tools against the live daemon: overview, connections,
listening ports, a program's signature and launch items, IP dossiers, recent alerts, launch
items, and LAN devices. It **cannot** block, kill, scan, or change anything; it recommends,
and you act. The answer lists the evidence it used and, under "How Claude checked", every
tool call. A typical investigation makes 3–8 tool calls.

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

## 🕵️ SOC analyst tools: Investigate & Email

Two dashboard tabs for day-to-day analyst work. Both are passive: nothing is scanned, opened or executed.

### Investigate: IPs, domains, URLs, hashes

Paste one indicator (defanged is fine: `hxxps://evil[.]com`, `1.2.3[.]4`) or a whole alert, ticket or report. A report gets every indicator extracted into a list you can filter, copy defanged, or export as CSV.

For one indicator, every source that understands its type is asked **in parallel**, and each answers in its own card:

| Source | Key | Types |
|---|---|---|
| PyNIDS (this Mac): your feeds, traffic seen, alerts | — | all |
| RDAP (WHOIS): owner, registrar, **domain age** | — | IP, domain, ASN |
| DNS records via Google DNS-over-HTTPS (A, MX, NS, TXT/SPF, PTR) | — | IP, domain |
| Shodan InternetDB: ports, tags, CVEs | — | IP |
| GreyNoise: internet noise vs targeted | optional | IP |
| urlscan.io search (existing scans only) | optional | IP, domain, URL, SHA-256 |
| Certificate Transparency (crt.sh): certs and subdomains | — | domain |
| VirusTotal | free key | IP, domain, URL, hash |
| AbuseIPDB | free key | IP |
| AlienVault OTX | free key | IP, domain, URL, hash |
| URLhaus · ThreatFox · MalwareBazaar (abuse.ch) | one free key | URL, domain, IP, hash |

* Every card shows a verdict, a summary, tags, and the **raw response exactly as received** (copyable), so you can always check the summary against the source.
* **Pivot** from any value in a result (a resolved IP, a name server, a payload hash). The trail of pivots is kept at the top.
* **Open in…** links go to 30+ web tools (Talos, X-Force, Shodan, Censys, Hybrid Analysis, Joe Sandbox, NVD …). Nothing is sent until you click.
* **Copy report** puts a defanged Markdown summary on the clipboard for a ticket.
* Results are cached (6 h for most sources), and free-tier rate limits are respected with automatic retry.
* Add keys under **Sources & API keys**. They are stored in the data folder (0600), and the dashboard can only see whether a key is set.

From the terminal: `pynids investigate 'hxxps://evil[.]com/login'` (add `--web` to open it in the dashboard, or `--json`).

### Email: phishing analysis that keeps the evidence

Drop an `.eml` file, paste the raw source, or click **Analyze in PyNIDS** in Thunderbird.

* **Nothing is lost.** The original is stored unchanged, read-only and named by its SHA-256, and every view is computed from it. Every header, MIME part and finding records its exact raw lines, so **every finding has a "lines 7–9" button** that jumps to the evidence.
* **Raw source viewer.** Headers are colored by group (routing, authentication, identity, MIME) and boundaries are marked. Hidden preamble/epilogue text is shaded red. Base64 blocks are folded until you expand them. URLs, IPs and addresses are clickable (they open Investigate). Invisible characters are shown as `⟨RLO⟩`, `⟨ZWSP⟩`, and bad bytes as `\xNN`. You can search inside it.
* **Decoding.** Handles base64 (and reports junk, padding problems and appended data), quoted-printable, uuencode, RFC 2047 encoded headers, RFC 2231 file names and every charset. Defects are reported, never silently repaired. Decoding is cross-checked against Python's email library in the tests.
* **Sender & authentication.** Shows the SPF/DKIM/DMARC verdicts and DKIM alignment. It flags a display name that hides another address, Reply-To or Return-Path mismatches, look-alike and punycode domains (`paypa1`, Cyrillic `а`), and invisible characters. The Received chain is shown as a hop table with delays and time anomalies.
* **Links from everywhere:** text, HTML attributes, CSS, PDFs and HTML attachments. SafeLinks, Proofpoint and Google redirects are unwrapped. Links are flagged for text that shows one site but goes to another, bare IPs, `user@host` tricks, shorteners, free hosting abused for phishing, and brand look-alikes.
* **Attachments, triaged in memory.** Real type from the file's bytes vs. its extension, double extensions, right-to-left override names, macros, password-protected archives (with contents), PDF active content (including hex-escaped keywords), RTF objects, HTML smuggling, plus hashes, hex view and strings. Downloads are saved as `.bin` only after a warning.
* **HTML preview** only on request, in a sandbox with scripts, forms, links and *all* remote content blocked, so tracking pixels never tell the sender you looked.
* **Indicators** found anywhere in the message can be investigated together in one click.

From the terminal: `pynids mail analyze message.eml` (`--local` works without the daemon).

### Thunderbird and VS Code

```bash
pynids mail thunderbird     # builds ~/Downloads/pynids-thunderbird.xpi
pynids mail token           # the token to paste into the add-on's options
pynids mail vscode          # .eml syntax highlighting for VS Code
```

Install the `.xpi` in Thunderbird from **Add-ons and Themes → ⚙ → Install Add-on From File…**. It adds **Analyze in PyNIDS** above each message and to the message-list context menu. It sends the message exactly as Thunderbird stored it, only to `127.0.0.1`.

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

host:
  signatures: true               # check code signatures of programs on the network
  baseline: true                 # learn, then flag new programs / new countries
  baseline_learning_hours: 24
  lan_inventory: true            # devices on your network + "new device" alerts
  c2_correlation: true           # the "Likely command-and-control" alert

lookups:
  mode: alerts             # alerts | always | manual — when IPs may be looked up automatically
  min_severity: MEDIUM     # for mode "alerts"
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
| `pynids ai ask "QUESTION"` | Let Claude investigate this Mac (read-only tools) |
| `pynids connections [--flagged] [--all] [--app NAME]` | Live connections with program, signature and risk flags |
| `pynids listening` | Listening ports and who can reach them |
| `pynids program PATH` | Signature, SHA-256, launch items and sockets of one executable |
| `pynids launch-items [--flagged]` | LaunchAgents / LaunchDaemons and the programs they start |
| `pynids lookup IP [--local]` | IP dossier: what PyNIDS saw, plus RDAP / reverse DNS / InternetDB |
| `pynids investigate VALUE [--web] [--json]` | Look up an IP / domain / URL / hash / email / ASN / CVE across all intel sources |
| `pynids mail analyze FILE.eml [--web] [--local]` | Phishing analysis of a raw email |
| `pynids mail thunderbird` / `token` / `vscode` | Thunderbird add-on, its token, VS Code .eml highlighting |
| `pynids devices [--scan IP]` | Devices on your LAN; identify one with nmap |
| `pynids allow list/add/remove` | Manage "Mark as expected" rules |
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

* **Everything stays on your Mac.** The only outbound requests are feed and GeoIP downloads, IP lookups, and, only when you ask, Claude.
* **IP lookups are limited on purpose.** Reverse DNS, RDAP and Shodan InternetDB lookups tell those services (and, for reverse DNS, whoever runs the IP's zone, possibly an attacker) that you are interested in an address. By default they run automatically only for IPs in MEDIUM-or-worse alerts (at most 40 an hour) and when you click **Look up**; private addresses are never sent. Set `lookups.mode: manual` to only look up on request.
* **nmap scans are refused for internet hosts.** Only private / link-local addresses and this Mac can be scanned, and only when you click.
* **The API listens on `127.0.0.1` only**, and a malicious webpage can't use it:
  * a **Host-header allowlist** blocks DNS-rebinding attacks
  * a **random token** is required for every data route
  * an **Origin check** protects every action that changes something
  * **no CORS headers** are sent, so other origins can't read responses
* **`/api/widget`** is the only open route, because the sandboxed widget can't read the token. It returns counts and alert headlines only.
* **Investigate and Email are passive.** Lookups go only to the sources listed in the dashboard (private IPs are never sent), and only when you investigate. Emails are parsed in memory. Nothing in them is opened, rendered, fetched or run unless you click **Render safely** (sandboxed, no network) or **Download .bin**.
* **The Thunderbird add-on** is the only non-dashboard origin the API accepts, only for submitting a message, and it still needs the token.
* **Secrets live outside the repo**, in `/Library/Application Support/PyNIDS/`, and `.gitignore` also blocks keys, key logs, captures, and databases.

### Files on disk

| Path | Contents |
|---|---|
| `/Library/LaunchDaemons/com.pynids.daemon.plist` | Background service definition |
| `/Library/Application Support/PyNIDS/config.yaml` | Your settings |
| `…/events.db` | Alert history, plus the learned baseline, LAN devices, and cached IP lookups |
| `…/intel/`, `…/geoip/` | Cached feeds, GeoIP databases |
| `…/api-token`, `…/anthropic-key` | API token (0644), Claude key (0600) |
| `…/blocklist.json` | Active blocks and why |
| `…/allowlist.json` | Rules you marked as expected |
| `…/paused` | Present while detection is stopped from the menu bar |
| `…/soc-keys.json` | API keys for Investigate sources (0600) |
| `…/evidence/email/` | Analysed emails, stored unchanged and read-only, named by SHA-256 |
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
| Menu bar shows ⏸ **"Stopped · not detecting"** | Detection was stopped. Click the shield → power menu → **Resume Detection** |
| Daemon won't start after **Quit PyNIDS Completely** | Quitting disables the service. Use **Start PyNIDS…** in the menu bar app, or `sudo launchctl enable system/com.pynids.daemon` then `sudo .venv/bin/pynids daemon restart` |
| "Many SSH connections" alerts while using git | Expected at MEDIUM when your Mac opens lots of SSH connections quickly. Add a suppression rule for the rule/destination if it's noisy |
| Widget numbers look stale | It refreshes every few minutes. Check the "Updated" time, or run `killall NotificationCenter` |
| World map is empty | Run `sudo .venv/bin/pynids geoip download` and restart. The map outline also needs internet access |
| Many **"Unattributed"** connections | Very short-lived connections can close before they're matched. Run `sudo .venv/bin/pynids daemon restart` to make sure the latest attribution code is loaded |
| **Explain with Claude** errors | Invalid key → `sudo .venv/bin/pynids ai set-key`. Rate limit → wait a minute. Also check your credit balance |
| Too many alerts of one kind | Add a suppression rule (see [Configuration](#-configuration)) or raise `notifications.min_severity` |
| `git commit` says *"Author identity unknown"* | `git config --global user.name "…"` and `git config --global user.email "…"` |
| `pynids: command not found` | Activate the venv in this window: `cd ~/NIDS && source .venv/bin/activate` |
| An Investigate card says **Needs an API key** | Add a free key under **Investigate → Sources & API keys** (see [step 8](#8-set-up-the-soc-tools-optional)) |
| A card says **Rate limited** | The free tier's per-minute limit was reached. The card retries by itself when the limit resets |
| crt.sh card **failed (HTTP 502/503)** | crt.sh is often overloaded. Press the card's refresh icon a minute later |
| Email shows **"No headers found"** | You pasted the visible text, not the source. Save or export the raw message (see the walkthrough above) |
| Thunderbird says **"PyNIDS isn't reachable"** | The daemon isn't running (`pynids status`), or the port in the add-on options isn't `8787` |
| Thunderbird says **token is wrong** / HTTP 401 | Copy a fresh token with `pynids mail token` into the add-on options. Reinstalling the daemon creates a new one |
| Dashboard doesn't show the new tabs after updating | `sudo .venv/bin/pynids daemon restart`, then reload the page |

---

## 🧹 Uninstall

```bash
sudo .venv/bin/pynids daemon uninstall                 # stops the service, lifts all blocks
rm -rf ~/Applications/PyNIDS.app                        # menu bar app + widget
sudo rm -rf "/Library/Application Support/PyNIDS" /Library/Logs/PyNIDS   # data, keys, analysed emails, logs
rm -rf ~/.vscode/extensions/pynids.pynids-eml-1.0.0      # VS Code .eml highlighting
```

Remove the Thunderbird add-on from **Add-ons and Themes → PyNIDS Email Analysis → Remove**.

---

## 🧪 For developers

### Tests

```bash
pip install -e ".[dev,all]"
pytest                                    # 372 tests
pytest tests/test_soc.py tests/test_mail.py   # just the SOC workbench and email analyser
pytest --cov=pynids --cov-report=term-missing
```

The email tests include a corpus of deliberately broken and malicious messages. A
cross-check builds varied messages with Python's own `email` package and asserts that every
part decodes to identical bytes. Investigate sources are tested against recorded responses, so
the suite never needs network access or API keys.

Tests use real protocol test vectors (for example the RFC 9001 QUIC keys) and cover every
detector, the raw-frame decoder, the plain-English guides, pausing detection, the
false-positive regressions above, the API security checks, pf guard rails, and the Claude
request shape.

### Project layout

```
pynids/
├── engine.py            detection pipeline
├── sniffer.py           live capture (raw BPF frames + decoder) / PCAP replay
├── protocols/           HTTP, DNS, TLS, QUIC (+ decryption), STUN, SSH, SMTP
├── detection/           signature, anomaly, behavioural, X-Ray (stealth) detectors
├── enrich/              app attribution (psutil + nettop), hostnames, GeoIP
├── host/                code signatures, socket table, launch items, IP dossiers, LAN inventory
├── intel/               threat intel index + live feeds
├── alerts/              alert model, manager, plain-English guide, outputs (SQLite, JSON, syslog, terminal)
├── response/            pf blocking, macOS notifications
├── ai/                  Explain with Claude, Ask Claude (investigation agent)
├── soc/                 Investigate (indicators, sources, workbench) and mail/ (lossless MIME parser, phishing analysis, evidence store)
├── integrations/        Thunderbird add-on, VS Code .eml grammar
├── service/             daemon, local API, live stats, launchd, PCAP recorder
├── web/dashboard.html   web dashboard (app/: Investigate + Email tabs, vendor/: offline map libraries)
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
alerts = engine.process_packet(meta)   # meta from pynids.sniffer.decode_frame() / packet_to_meta()
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
