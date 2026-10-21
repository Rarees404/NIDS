"""
CLI commands for the always-on macOS service and its companions.

daemon    run / install / uninstall / restart / status / logs
status    one-screen health summary from the running daemon
open      open the web dashboard
intel     update / show the live threat-intel feeds
geoip     download the free DB-IP GeoIP databases
block     add / remove / list / flush pf blocks
ai        set-key / explain / ask — Claude-powered analysis and investigation
connections, listening, program, launch-items, lookup, devices
          what's running, what's exposed, who owns an IP, who's on the LAN
allow     list / add / remove "expected" alert rules
keylog    launch a browser that logs TLS keys (for decryption)
decrypt   decrypt recorded traffic with tshark + a TLS key log
app       build and install the menu bar app + widget
update    check GitHub for a new version and install it
"""
from __future__ import annotations

import getpass
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .cli import main
from .paths import SYSTEM_DIR, data_dir, geoip_dir, intel_dir, is_root

console = Console()

_SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan"}


def _client():
    from .service.client import ApiClient
    return ApiClient()


def _fail(message: str) -> None:
    console.print(f"[red]{message}[/red]")
    sys.exit(1)


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} PB"


# ---------------------------------------------------------------------------
# daemon
# ---------------------------------------------------------------------------

@main.group()
def daemon() -> None:
    """Run PyNIDS as an always-on background service (launchd)."""


@daemon.command("run")
@click.option("--config", "-c", default=None, metavar="FILE", help="YAML config (default: data dir config.yaml).")
@click.option("--rules", "-r", default=None, metavar="FILE", help="Signature rules YAML.")
@click.option("--iface", "-i", default=None, help="Interface to capture (default: follow the default route).")
@click.option("--port", default=None, type=int, help="API / dashboard port (default 8787).")
@click.option("--auto-block/--no-auto-block", default=None, help="Override response.auto_block.")
@click.option("--record/--no-record", default=None, help="Keep a rolling PCAP window for `pynids decrypt`.")
def daemon_run(config, rules, iface, port, auto_block, record) -> None:
    """Run the daemon in the foreground (this is what launchd runs)."""
    from .service.daemon import DaemonOptions, run_daemon

    while True:
        code = run_daemon(DaemonOptions(
            config=config, rules=rules, interface=iface, api_port=port,
            auto_block=auto_block, record=record,
        ))
        if code != 75:  # 75 = network changed, restart capture in-process
            sys.exit(code)
        time.sleep(1)


@daemon.command("install")
@click.option("--rules", "-r", default=None, metavar="FILE", help="Signature rules YAML to load.")
@click.option("--record", is_flag=True, help="Keep a rolling PCAP window for `pynids decrypt`.")
def daemon_install(rules: Optional[str], record: bool) -> None:
    """Install and start the background service (runs at boot, as root)."""
    from .service import launchd

    if not is_root():
        _fail("Installing the service needs root:  sudo pynids daemon install")
    SYSTEM_DIR.mkdir(parents=True, exist_ok=True)
    cfg = SYSTEM_DIR / "config.yaml"
    if not cfg.exists():
        shutil.copy(Path(__file__).parent / "service" / "default_config.yaml", cfg)
        console.print(f"Wrote default config → [bold]{cfg}[/bold]")
    args: List[str] = []
    if rules:
        args += ["--rules", str(Path(rules).resolve())]
    if record:
        args.append("--record")
    # Installing means "start monitoring": drop a leftover Stop Detection.
    from .paths import paused_flag_path
    paused_flag_path().unlink(missing_ok=True)
    path = launchd.install(extra_args=args)
    console.print(f"[green]✓[/green] Installed [bold]{path}[/bold] and started the daemon")
    from .service.client import ApiClient
    client = ApiClient(token="")
    for _ in range(40):
        if client.alive():
            break
        time.sleep(0.5)
    console.print(Panel(
        "Dashboard  [bold]http://127.0.0.1:8787[/bold]   (or: pynids open)\n"
        "Status     pynids status\n"
        "Logs       pynids daemon logs -f\n"
        f"Config     {cfg}",
        title="PyNIDS is running", expand=False,
    ))
    if not (geoip_dir() / "dbip-city-lite.mmdb").exists():
        console.print("[dim]Tip: enable the world map with  sudo pynids geoip download[/dim]")


@daemon.command("uninstall")
def daemon_uninstall() -> None:
    """Stop the background service and remove it from launchd."""
    from .service import launchd

    if not is_root():
        _fail("Removing the service needs root:  sudo pynids daemon uninstall")
    try:
        from .response.pf import PfBlocker
        removed = PfBlocker().flush()
        if removed:
            console.print(f"Lifted {removed} pf block(s)")
    except Exception:  # noqa: BLE001
        pass
    if launchd.uninstall():
        console.print("[green]✓[/green] Daemon stopped and removed (data kept in "
                      f"{SYSTEM_DIR})")
    else:
        console.print("The daemon was not installed.")


@daemon.command("restart")
def daemon_restart() -> None:
    """Restart the background service (applies config changes)."""
    from .service import launchd

    launchd.restart()
    console.print("[green]✓[/green] Restarted")


@daemon.command("logs")
@click.option("--follow", "-f", is_flag=True, help="Keep streaming new lines.")
@click.option("--lines", "-n", default=60, show_default=True)
def daemon_logs(follow: bool, lines: int) -> None:
    """Show the daemon log."""
    from .service.launchd import LOG_FILE

    if not LOG_FILE.exists():
        _fail(f"No log yet at {LOG_FILE}")
    args = ["tail", "-n", str(lines)] + (["-F"] if follow else []) + [str(LOG_FILE)]
    try:
        subprocess.run(args, check=False)
    except KeyboardInterrupt:
        pass


@daemon.command("status")
def daemon_status() -> None:
    """Show whether the service is installed and running."""
    _print_status()


@main.command("status")
def status_cmd() -> None:
    """One-screen health summary of the running daemon."""
    _print_status()


def _print_status() -> None:
    from .service import launchd
    from .service.client import DaemonUnavailable

    installed = launchd.is_installed()
    try:
        s = _client().get("/api/summary")
    except DaemonUnavailable:
        console.print(Panel(
            ("Installed but not responding — check  pynids daemon logs"
             if installed else "Not installed.  Start with:  sudo pynids daemon install"),
            title="PyNIDS daemon", border_style="red", expand=False,
        ))
        sys.exit(1)
    except RuntimeError as exc:
        _fail(f"{exc} (is the API token readable? try sudo)")

    st = s.get("status", {})
    level_style = {"ok": "green", "notice": "yellow", "warning": "red", "critical": "bold white on red"}
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="dim")
    t.add_column()
    t.add_row("State", f"[bold]{st.get('state')}[/bold] on {' + '.join(st.get('interfaces') or ['—'])}"
                       f"  ·  up {st.get('uptime', 0) // 60} min")
    t.add_row("Threat level", Text(s.get("level", "ok").upper(), style=level_style.get(s.get("level"), "")))
    t.add_row("Traffic", f"{s['packets']:,} packets · {_fmt_bytes(s['bytes'])} · "
                         f"{s['rates']['pps']} pkt/s now")
    k = s["kinds"]
    t.add_row("Events", f"{s['events_total']:,} total — threats {k.get('threat', 0) + k.get('attack', 0)}, "
                        f"trackers {k.get('tracker', 0) + k.get('beacon', 0)}, "
                        f"leaks/probes {k.get('webrtc', 0) + k.get('localhost', 0)}, "
                        f"encrypted DNS {k.get('doh', 0)}")
    t.add_row("Reach", f"{s['remote_count']:,} endpoints in {s['country_count']} countries")
    t.add_row("Apps", ", ".join(f"{a['app']} ({_fmt_bytes(a['bytes'])})" for a in s["top_apps"]) or "—")
    onoff = lambda v: "[green]on[/green]" if v else "[dim]off[/dim]"  # noqa: E731
    t.add_row("Features",
              f"app attribution {onoff(st.get('process_attribution'))} · GeoIP {onoff(st.get('geoip'))} · "
              f"notifications {onoff(st.get('notifications'))} · auto-block {onoff(st.get('auto_block'))} · "
              f"Claude {onoff(st.get('ai'))}")
    t.add_row("Blocked IPs", str(s.get("blocked", 0)))
    age = st.get("feeds_age_hours")
    t.add_row("Threat intel", "not downloaded yet" if age is None else f"feeds {age} h old")
    if s.get("last_alert"):
        la = s["last_alert"]
        t.add_row("Latest alert", Text(f"{la['severity']} ", style=_SEV_STYLE.get(la["severity"], "")) +
                  Text(la["message"][:100]))
    console.print(Panel(t, title="PyNIDS", subtitle="http://127.0.0.1:8787", expand=False))


@main.command("open")
def open_cmd() -> None:
    """Open the live web dashboard in your browser."""
    client = _client()
    if not client.alive():
        _fail("The daemon is not running. Start it with:  sudo pynids daemon install")
    subprocess.run(["open", client.dashboard_url], check=False)


# ---------------------------------------------------------------------------
# intel
# ---------------------------------------------------------------------------

@main.group()
def intel() -> None:
    """Live threat-intelligence feeds (abuse.ch, Spamhaus, Tor, Disconnect, DoH lists)."""


@intel.command("update")
def intel_update() -> None:
    """Download all feeds now."""
    from .intel import feeds
    from .service.client import DaemonUnavailable

    try:
        results = _client().post("/api/intel/update", timeout=180)
        console.print("[dim]Updated through the running daemon (reloaded live).[/dim]")
    except (DaemonUnavailable, RuntimeError):
        if not os.access(intel_dir(), os.W_OK):
            _fail(f"Cannot write {intel_dir()} — run with sudo")
        results = [r.__dict__ for r in feeds.update_feeds()]
    t = Table(title="Threat-intel feeds")
    t.add_column("Feed")
    t.add_column("Result")
    t.add_column("Entries", justify="right")
    for r in results:
        t.add_row(r["name"], "[green]ok[/green]" if r["ok"] else f"[red]{r['error']}[/red]",
                  f"{r['entries']:,}" if r["ok"] else "—")
    console.print(t)


@intel.command("status")
def intel_status() -> None:
    """Show cached feeds and their age."""
    from .intel import feeds

    t = Table(title=f"Threat-intel cache ({intel_dir()})")
    t.add_column("Feed")
    t.add_column("Used for")
    t.add_column("Entries", justify="right")
    t.add_column("Fetched")
    for row in feeds.feed_status():
        fetched = datetime.fromtimestamp(row["fetched"]).strftime("%Y-%m-%d %H:%M") if row["fetched"] else "never"
        t.add_row(row["name"], row["description"], f"{row['entries']:,}", fetched)
    console.print(t)


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

@main.command("update")
@click.option("--check", "check_only", is_flag=True, help="Only check; don't install.")
@click.option("--yes", "-y", is_flag=True, help="Install without asking.")
def update_cmd(check_only: bool, yes: bool) -> None:
    """Check GitHub for a new version and install it (through the running daemon)."""
    from .service.client import DaemonUnavailable

    client = _client()
    try:
        info = client.post("/api/update/check", timeout=120)
    except (DaemonUnavailable, RuntimeError) as exc:
        _fail(str(exc))
    if info.get("error"):
        _fail(info["error"])
    if not info.get("available"):
        console.print(f"[green]PyNIDS is up to date[/green] ({info.get('current_version')}, {info.get('current_commit')}).")
        return
    latest = info.get("latest_version") or info.get("latest_commit")
    console.print(f"[bold]Update available:[/bold] {info.get('current_version')} → {latest} "
                  f"({info['behind']} new change{'s' if info['behind'] > 1 else ''})")
    for c in info.get("commits") or []:
        console.print(f"  [dim]{c['sha']}[/dim] {c['subject']}")
    if info.get("blocked"):
        _fail(info["blocked"])
    if check_only or not (yes or click.confirm("Install it now?", default=True)):
        return
    try:
        client.post("/api/update")
    except (DaemonUnavailable, RuntimeError) as exc:
        _fail(str(exc))
    step = None
    with console.status("Updating…") as spinner:
        for _ in range(900):
            time.sleep(1)
            try:
                info = client.get("/api/update", timeout=3)
            except (DaemonUnavailable, RuntimeError):
                continue  # restarting
            if info.get("step") and info["step"] != step:
                step = info["step"]
                spinner.update(step)
            if info.get("state") == "error":
                _fail(info.get("error") or "Update failed")
            if info.get("state") in ("idle", "restart-needed") and not info.get("available"):
                break
    console.print(f"[green]Updated to {info.get('current_version')}[/green] ({info.get('current_commit')}).")
    if info.get("state") == "restart-needed":
        console.print("Restart the daemon to finish: sudo .venv/bin/pynids daemon restart")
    if (info.get("last_update") or {}).get("app_changed"):
        console.print("The menu bar app rebuilds itself on its next refresh (or run: pynids app).")


# ---------------------------------------------------------------------------
# geoip
# ---------------------------------------------------------------------------

@main.group()
def geoip() -> None:
    """Offline GeoIP / ASN databases (DB-IP Lite, CC BY 4.0)."""


@geoip.command("download")
def geoip_download() -> None:
    """Download this month's DB-IP City Lite and ASN Lite databases (~70 MB)."""
    from .enrich.geo import download_databases

    if not os.access(geoip_dir(), os.W_OK):
        _fail(f"Cannot write {geoip_dir()} — run with sudo")
    with console.status("Downloading DB-IP databases…"):
        files = download_databases()
    for f in files:
        console.print(f"[green]✓[/green] {f}")
    console.print("[dim]IP geolocation by DB-IP (https://db-ip.com). "
                  "Restart the daemon to load it: sudo pynids daemon restart[/dim]")


@geoip.command("lookup")
@click.argument("ip")
def geoip_lookup(ip: str) -> None:
    """Look up one IP address."""
    from .enrich.geo import GeoResolver

    geo = GeoResolver()
    if not geo.available:
        _fail("No GeoIP database yet — run: sudo pynids geoip download")
    console.print_json(json.dumps(geo.lookup(ip) or {}))


# ---------------------------------------------------------------------------
# block
# ---------------------------------------------------------------------------

@main.group()
def block() -> None:
    """Block IPs with the macOS pf firewall (via the running daemon)."""


@block.command("add")
@click.argument("ip")
@click.option("--reason", default="Blocked from the command line")
@click.option("--ttl", default=3600, show_default=True, help="Seconds until the block lifts (0 = never).")
def block_add(ip: str, reason: str, ttl: int) -> None:
    """Block all traffic to and from IP."""
    try:
        entry = _client().post("/api/blocks", {"ip": ip, "reason": reason, "ttl": ttl or None})
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    until = datetime.fromtimestamp(entry["expires"]).strftime("%H:%M") if entry.get("expires") else "never"
    console.print(f"[green]✓[/green] Blocked [bold]{ip}[/bold] (lifts at {until})")


@block.command("remove")
@click.argument("ip")
def block_remove(ip: str) -> None:
    """Lift a block."""
    try:
        r = _client().delete(f"/api/blocks/{ip}")
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    console.print(f"[green]✓[/green] Unblocked {ip}" if r.get("removed") else f"{ip} was not blocked")


@block.command("list")
def block_list() -> None:
    """Show blocked IPs."""
    try:
        rows = _client().get("/api/blocks")
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    if not rows:
        console.print("[dim]No IPs are blocked.[/dim]")
        return
    t = Table()
    t.add_column("IP")
    t.add_column("Reason")
    t.add_column("Source")
    t.add_column("Expires")
    for r in rows:
        exp = datetime.fromtimestamp(r["expires"]).strftime("%H:%M") if r.get("expires") else "never"
        t.add_row(r["ip"], r["reason"][:70], r["source"], exp)
    console.print(t)


@block.command("flush")
@click.confirmation_option(prompt="Lift every PyNIDS block?")
def block_flush() -> None:
    """Lift every block."""
    rows = _client().get("/api/blocks")
    for r in rows:
        _client().delete(f"/api/blocks/{r['ip']}")
    console.print(f"[green]✓[/green] Lifted {len(rows)} block(s)")


# ---------------------------------------------------------------------------
# ai
# ---------------------------------------------------------------------------

@main.group()
def ai() -> None:
    """Claude-powered plain-English alert explanations."""


@ai.command("set-key")
def ai_set_key() -> None:
    """Store an Anthropic API key for the daemon (file mode 0600)."""
    from .ai.explain import save_api_key
    from .paths import anthropic_key_path

    if not os.access(anthropic_key_path().parent, os.W_OK):
        _fail("Run with sudo so the root daemon can read the key:  sudo pynids ai set-key")
    key = getpass.getpass("Anthropic API key (input hidden): ").strip()
    if not key:
        _fail("No key entered.")
    save_api_key(key)
    console.print(f"[green]✓[/green] Saved to {anthropic_key_path()} — "
                  "use “Explain with Claude” in the dashboard or: pynids ai explain <alert-id>")


@ai.command("explain")
@click.argument("alert_id")
def ai_explain(alert_id: str) -> None:
    """Explain one alert (ID from the dashboard or `pynids query --json`)."""
    try:
        with console.status("Claude is analysing the alert…"):
            r = _client().post(f"/api/explain/{alert_id}", timeout=180)
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    from rich.markdown import Markdown
    console.print(Panel(Markdown(r["text"]), title=f"{r.get('verdict') or 'Analysis'} · {r['model']}",
                        expand=False))


@ai.command("ask")
@click.argument("question", nargs=-1, required=True)
def ai_ask(question) -> None:
    """Let Claude investigate this Mac with read-only tools and answer a question."""
    try:
        with console.status("Claude is investigating (connections, programs, alerts)…"):
            r = _client().post("/api/investigate", {"question": " ".join(question)}, timeout=600)
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    from rich.markdown import Markdown
    console.print(Panel(Markdown(r["text"]), title=f"{r.get('verdict') or 'Answer'} · {r['model']}", expand=False))
    if r.get("steps"):
        console.print("[dim]Tools used: " + ", ".join(s["tool"] for s in r["steps"]) + "[/dim]")


# ---------------------------------------------------------------------------
# host inspection: connections, listening ports, programs, launch items,
# IP lookups, LAN devices, allowlist
# ---------------------------------------------------------------------------

_RISK = {0: "[green]ok[/green]", 1: "[yellow]unusual[/yellow]", 2: "[bold red]suspicious[/bold red]",
         3: "[bold white on red] high [/bold white on red]"}
_SIG = {"apple": "[green]Apple[/green]", "app_store": "[green]App Store[/green]",
        "developer_id": "[green]Developer ID[/green]", "development": "[yellow]Development[/yellow]",
        "adhoc": "[yellow]Ad-hoc[/yellow]", "unsigned": "[red]Unsigned[/red]",
        "invalid": "[bold red]Broken[/bold red]", None: "[dim]…[/dim]"}


def _get(path: str):
    try:
        return _client().get(path, timeout=60)
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))


@main.command("connections")
@click.option("--all", "show_all", is_flag=True, help="Include LAN connections, not just the internet.")
@click.option("--flagged", is_flag=True, help="Only risky connections.")
@click.option("--app", default=None, help="Filter by app name (substring).")
def connections_cmd(show_all: bool, flagged: bool, app: Optional[str]) -> None:
    """Live connections and the program behind each (a better netstat)."""
    snap = _get("/api/connections")
    rows = snap["connections"]
    if flagged:
        rows = [r for r in rows if r["risk"] >= 2]
    elif not show_all:
        rows = [r for r in rows if r["scope"] == "internet"]
    if app:
        rows = [r for r in rows if app.lower() in (r.get("app") or "").lower()]
    s = snap["summary"]
    console.print(f"[bold]{s['connections']}[/bold] connections · {s['programs']} programs · "
                  f"[{'red' if s['flagged_programs'] else 'green'}]{s['flagged_programs']} flagged[/] · "
                  f"{s['exposed_ports']} exposed ports")
    if not rows:
        console.print("[dim]Nothing matches.[/dim]")
        return
    t = Table()
    for col in ("Risk", "App", "PID", "Remote", "Port", "Where", "Signature", "Flags"):
        t.add_column(col)
    labels = snap.get("flag_labels", {})
    for r in rows[:200]:
        remote = (r.get("remote_host") + "\n" if r.get("remote_host") else "") + (r.get("remote_ip") or "")
        t.add_row(_RISK.get(r["risk"], "?"), r.get("app") or r.get("process") or "?", str(r.get("pid") or ""),
                  remote, f"{r['proto']}/{r.get('remote_port')}",
                  ", ".join(x for x in (r.get("country"), r.get("org")) if x),
                  _SIG.get(r.get("signature"), r.get("signature") or ""),
                  ", ".join(labels.get(f, f) for f in r.get("flags") or []))
    console.print(t)


@main.command("listening")
def listening_cmd() -> None:
    """Listening ports and who can reach them."""
    rows = _get("/api/connections")["listening"]
    t = Table()
    for col in ("Reachable from", "Program", "PID", "Port", "Addresses", "Signature"):
        t.add_column(col)
    for r in rows:
        style = "bold" if "exposed" in r.get("flags", []) else ""
        t.add_row(f"[{style}]{r['exposure_label']}[/]" if style else r["exposure_label"],
                  r.get("app") or r.get("process") or "?", str(r.get("pid") or ""),
                  f"{r['proto']}/{r['local_port']}", ", ".join(a or "*" for a in r.get("addresses") or []),
                  _SIG.get(r.get("signature"), r.get("signature") or ""))
    console.print(t)


@main.command("program")
@click.argument("exe")
def program_cmd(exe: str) -> None:
    """Signature, hash, launch items and sockets of one executable."""
    from urllib.parse import quote
    p = _get("/api/program?exe=" + quote(os.path.abspath(exe)))
    sig, a = p.get("signature") or {}, p.get("assessment") or {}
    lines = [f"[bold]{p['app']}[/bold]  {_RISK.get(a.get('risk'), '')}", p["exe"], "",
             f"Signature:  {sig.get('label') or sig.get('status')}" + (f" — {sig['authority']}" if sig.get("authority") else ""),
             f"SHA-256:    {p.get('sha256') or '—'}"]
    if a.get("reasons"):
        lines.append("Why:        " + "; ".join(a["reasons"]))
    for j in p.get("launchd") or []:
        lines.append(f"Starts via: {j['label']}  ({j['plist']})")
    if p.get("virustotal"):
        lines.append(f"VirusTotal: {p['virustotal']}")
    console.print(Panel("\n".join(lines), expand=False))


@main.command("launch-items")
@click.option("--flagged", is_flag=True, help="Only items with risk flags.")
def launch_items_cmd(flagged: bool) -> None:
    """Programs macOS starts automatically (LaunchAgents / LaunchDaemons)."""
    rows = _get("/api/launch-items")
    if flagged:
        rows = [r for r in rows if r["risk"] >= 1 or "missing_program" in r["flags"]]
    t = Table()
    for col in ("Risk", "Label", "Kind", "Program", "Signature", "Flags"):
        t.add_column(col)
    for r in rows:
        t.add_row(_RISK.get(r["risk"], "?"), r["label"], r["kind"], r.get("program") or "—",
                  _SIG.get(r.get("signature"), r.get("signature") or ""), ", ".join(r["flags"]))
    console.print(t)


@main.command("lookup")
@click.argument("ip")
@click.option("--external/--local", default=True, show_default=True,
              help="Also ask RDAP, reverse DNS and Shodan InternetDB (sends the IP to them).")
def lookup_cmd(ip: str, external: bool) -> None:
    """Everything known about an IP: what PyNIDS saw, owner, reputation."""
    d = _get(f"/api/dossier/{ip}" + ("?external=1" if external else ""))
    L, X = d.get("local") or {}, d.get("external") or {}
    rdap, idb = X.get("rdap") or {}, X.get("internetdb") or {}
    rows = [
        ("Seen as", L.get("remote_host")), ("Apps", ", ".join(L.get("apps") or [])),
        ("Location", ", ".join(x for x in (L.get("city"), L.get("country_name") or L.get("country")) if x)),
        ("Network", L.get("org")), ("Threat intel", (L.get("intel") or {}).get("description") or "no match"),
        ("Reverse DNS", X.get("ptr")), ("Owner", rdap.get("owner")),
        ("Range", rdap.get("cidr") or rdap.get("range")), ("Abuse", rdap.get("abuse_email")),
        ("Open ports", ", ".join(map(str, idb.get("ports") or [])) if idb.get("listed") else None),
        ("Tags", ", ".join(idb.get("tags") or [])), ("CVEs", ", ".join((idb.get("vulns") or [])[:8])),
        ("Note", X.get("reason")),
    ]
    t = Table(show_header=False, box=None)
    for k, v in rows:
        if v:
            t.add_row(f"[dim]{k}[/dim]", str(v))
    console.print(Panel(t, title=ip, expand=False))
    for a in (L.get("recent_alerts") or [])[:8]:
        console.print(f"  [{_SEV_STYLE.get(a['severity'], '')}]{a['severity']:<8}[/] {a['message'][:100]}")


_VERDICT_STYLE = {"malicious": "bold red", "suspicious": "yellow", "clean": "green", "info": "cyan", "unknown": "dim"}


@main.command("investigate")
@click.argument("indicator", nargs=-1, required=True)
@click.option("--web", is_flag=True, help="Open the investigation in the dashboard instead.")
@click.option("--refresh", is_flag=True, help="Skip cached results.")
@click.option("--json", "as_json", is_flag=True, help="Print the raw results as JSON.")
def investigate_cmd(indicator: tuple, web: bool, refresh: bool, as_json: bool) -> None:
    """Look up an IP, domain, URL, hash, email, ASN or CVE across intel sources.

    Defanged input works:  pynids investigate 'hxxps://evil[.]com/login'
    """
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import quote

    text = " ".join(indicator)
    client = _client()
    if web:
        subprocess.run(["open", client.dashboard_url + "#investigate/" + quote(text, safe="")], check=False)
        return
    parsed = _client().post("/api/soc/parse", {"text": text}, timeout=30) if client.alive() else None
    if parsed is None:
        _fail("The daemon is not running. Start it with:  sudo pynids daemon install")
    if not parsed["iocs"]:
        _fail("No indicator recognised.")
    if not parsed["single"]:
        t = Table(title=f"{len(parsed['iocs'])} indicators found")
        t.add_column("Type")
        t.add_column("Indicator")
        t.add_column("Defanged", style="dim")
        for i in parsed["iocs"]:
            t.add_row(i["type"], i["value"], i["defanged"])
        console.print(t)
        return
    ioc = parsed["iocs"][0]
    sources = {s["name"]: s for s in _get("/api/soc/sources")}

    def one(name: str):
        return _client().post("/api/soc/lookup", {"source": name, "type": ioc["type"], "value": ioc["value"],
                                                  "refresh": refresh}, timeout=90)

    with console.status(f"Asking {len(ioc['sources'])} sources about {ioc['defanged']}…"):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(one, ioc["sources"]))
    if as_json:
        click.echo(json.dumps({"indicator": ioc, "results": results}, indent=2, default=str))
        return
    rank = {"unknown": 0, "info": 1, "clean": 2, "suspicious": 3, "malicious": 4}
    worst = max((r["verdict"] for r in results if r["status"] == "ok"), key=lambda v: rank.get(v, 0), default="unknown")
    console.print(Panel(f"[bold]{ioc['value']}[/bold]  [dim]{ioc['type']} · {ioc['defanged']}[/dim]\n"
                        f"Overall: [{_VERDICT_STYLE[worst]}]{worst}[/]", expand=False))
    for r in sorted(results, key=lambda r: -rank.get(r["verdict"], 0) if r["status"] == "ok" else 1):
        label = sources.get(r["source"], {}).get("label", r["source"])
        if r["status"] != "ok":
            console.print(f"[dim]{label}: {r['status'].replace('_', ' ')}{' — ' + r['message'] if r.get('message') else ''}[/dim]")
            continue
        t = Table(show_header=False, box=None, title=f"{label} · [{_VERDICT_STYLE.get(r['verdict'], '')}]{r['verdict']}[/]",
                  title_justify="left")
        for k, v in r["summary"]:
            if isinstance(v, list):
                n = 5 if v and isinstance(v[0], dict) else 8
                v = "\n".join(str(x if not isinstance(x, dict) else
                                  " · ".join(str(x[k]) for k in ("time", "url", "ip", "country") if x.get(k)))
                              for x in v[:n]) + (f"\n… {len(v) - n} more" if len(v) > n else "")
            t.add_row(f"[dim]{k}[/dim]", str(v))
        if r.get("tags"):
            t.add_row("[dim]Tags[/dim]", ", ".join(r["tags"]))
        console.print(t)
        console.print()


@main.group("mail")
def mail_group() -> None:
    """Email forensics: analyse .eml files, set up Thunderbird / VS Code."""


@mail_group.command("analyze")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--web", is_flag=True, help="Open the analysis in the dashboard.")
@click.option("--json", "as_json", is_flag=True, help="Print the full analysis as JSON.")
@click.option("--local", is_flag=True, help="Analyse in this process; don't store it in the service.")
def mail_analyze(path: Path, web: bool, as_json: bool, local: bool) -> None:
    """Analyse a raw email (.eml): sender, authentication, links, attachments."""
    data = path.read_bytes()
    if local:
        from .soc.mail.analyze import analyze
        result = analyze(data, path.name)
    else:
        client = _client()
        if not client.alive():
            _fail("The daemon is not running (use --local to analyse without it).")
        try:
            result = client.request("POST", "/api/soc/email", raw=data, timeout=120,
                                    headers={"Content-Type": "message/rfc822", "X-Filename": path.name, "X-Source": "cli"})
        except Exception as exc:  # noqa: BLE001
            _fail(str(exc))
        if web:
            subprocess.run(["open", client.dashboard_url + "#email/" + result["sha256"]], check=False)
            return
    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return
    s = result["summary"]
    risk_style = {"high": "bold red", "medium": "yellow", "low": "cyan", "none": "green"}[result["risk"]]
    head = Table(show_header=False, box=None)
    for k in ("subject", "from", "reply_to", "return_path", "to", "date"):
        if s.get(k):
            head.add_row(f"[dim]{k.replace('_', '-').title()}[/dim]", s[k])
    v = result["auth"]["verdicts"]
    head.add_row("[dim]SPF/DKIM/DMARC[/dim]", " / ".join(v.get(k, "—") for k in ("spf", "dkim", "dmarc")))
    head.add_row("[dim]SHA-256[/dim]", result["sha256"])
    console.print(Panel(head, title=f"[{risk_style}]{result['risk'].upper()} RISK[/]", expand=False))
    sev = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}
    for f in result["findings"]:
        where = f" [dim](lines {f['lines'][0]}–{f['lines'][1]})[/dim]" if f.get("lines") else ""
        console.print(f"  [{sev[f['severity']]}]{f['severity']:<6}[/] {f['title']}{where}")
        if f.get("detail"):
            console.print(f"         [dim]{f['detail'][:160]}[/dim]")
    if result["links"]:
        console.print("\n[bold]Links[/bold]")
        for l in result["links"][:30]:
            console.print(f"  {l['defanged']}  [dim]{', '.join(l['flags'])}[/dim]")
    for a in result["attachments"]:
        console.print(f"\n[bold]Attachment[/bold] {a['filename'] or a['part']} · {a['triage'].get('detected') or a['content_type']} · "
                      f"{a['size']:,} bytes\n  sha256 {a['hashes']['sha256']}")


@mail_group.command("token")
def mail_token() -> None:
    """Print the API token (paste it into the Thunderbird add-on options)."""
    from .paths import read_api_token
    token = read_api_token()
    if not token:
        _fail("No token yet — start the daemon first:  sudo pynids daemon install")
    click.echo(token)


@mail_group.command("thunderbird")
@click.option("--out", type=click.Path(file_okay=False, path_type=Path), default=Path.home() / "Downloads",
              show_default=True, help="Where to write the add-on.")
def mail_thunderbird(out: Path) -> None:
    """Build the Thunderbird add-on (.xpi) that sends messages to PyNIDS."""
    import zipfile
    from importlib import resources

    src = resources.files("pynids.integrations").joinpath("thunderbird")
    out.mkdir(parents=True, exist_ok=True)
    xpi = out / "pynids-thunderbird.xpi"
    with zipfile.ZipFile(xpi, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("manifest.json", "background.js", "options.html", "options.js", "icon.svg"):
            z.writestr(name, src.joinpath(name).read_bytes())
    console.print(f"[green]Built[/green] {xpi}\n")
    console.print("Install: Thunderbird → Tools → Add-ons and Themes → ⚙ → Install Add-on From File… → pick the .xpi")
    console.print("Then open the add-on's options and paste the token from:  [bold]pynids mail token[/bold]")
    console.print("Use it from the [bold]Analyze in PyNIDS[/bold] button above a message, or right-click messages in the list.")


@mail_group.command("vscode")
def mail_vscode() -> None:
    """Install .eml syntax highlighting for VS Code (header groups, boundaries, links)."""
    from importlib import resources

    src = resources.files("pynids.integrations").joinpath("vscode-eml")
    dest = Path.home() / ".vscode" / "extensions" / "pynids.pynids-eml-1.0.0"
    for rel in ("package.json", "language-configuration.json", "syntaxes/eml.tmLanguage.json"):
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.joinpath(rel).read_bytes())
    console.print(f"[green]Installed[/green] {dest}\nRestart VS Code, then open any .eml file (or pick the “Email source” language).")


@main.command("devices")
@click.option("--scan", "scan_ip", default=None, metavar="IP", help="Identify a LAN device with nmap.")
def devices_cmd(scan_ip: Optional[str]) -> None:
    """Devices seen on your local network (optionally nmap-scan one)."""
    if scan_ip:
        try:
            with console.status(f"Scanning {scan_ip}…"):
                r = _client().post("/api/devices/scan", {"ip": scan_ip}, timeout=300)
        except Exception as exc:  # noqa: BLE001
            _fail(str(exc))
        t = Table(title=f"{scan_ip} · {len(r['ports'])} open")
        for col in ("Port", "Service", "Product"):
            t.add_column(col)
        for p in r["ports"]:
            t.add_row(f"{p['proto']}/{p['port']}", p.get("service") or "", p.get("product") or "")
        console.print(t)
        return
    r = _get("/api/devices")
    t = Table()
    for col in ("IP", "Name", "Vendor", "MAC", "Online", "First seen"):
        t.add_column(col)
    for d in r["devices"]:
        t.add_row(d["ip"], d.get("name") or "", d.get("vendor") or ("(private address)" if d.get("randomized_mac") else ""),
                  d["mac"], "yes" if d["online"] else "no",
                  datetime.fromtimestamp(d["first_seen"]).strftime("%Y-%m-%d %H:%M"))
    console.print(t)
    if not r.get("nmap"):
        console.print("[dim]Install nmap (brew install nmap) to identify devices with --scan.[/dim]")


@main.group()
def allow() -> None:
    """Alerts you've marked as expected (the allowlist)."""


@allow.command("list")
def allow_list() -> None:
    rows = _get("/api/allowlist")
    if not rows:
        console.print("[dim]No rules.[/dim]")
        return
    t = Table()
    for col in ("ID", "Matches", "Silenced", "Note"):
        t.add_column(col)
    for r in rows:
        match = ", ".join(f"{k}={r[k]}" for k in ("kind", "rule_id", "app", "host", "ip") if r.get(k))
        t.add_row(r["id"], match, str(r.get("hits", 0)), r.get("note") or "")
    console.print(t)


@allow.command("add")
@click.option("--kind", default=None, help="tracker, beacon, quic, attack, host …")
@click.option("--rule", "rule_id", default=None, help="Exact rule ID, e.g. STEALTH-TRACKER.")
@click.option("--app", default=None)
@click.option("--host", default=None, help="Hostname; covers subdomains.")
@click.option("--ip", default=None)
@click.option("--note", default="")
def allow_add(kind, rule_id, app, host, ip, note) -> None:
    try:
        r = _client().post("/api/allowlist", {"kind": kind, "rule_id": rule_id, "app": app, "host": host,
                                              "ip": ip, "note": note})
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    console.print(f"[green]✓[/green] Added rule {r['id']}")


@allow.command("remove")
@click.argument("rule_id")
def allow_remove(rule_id: str) -> None:
    try:
        r = _client().delete(f"/api/allowlist/{rule_id}")
    except Exception as exc:  # noqa: BLE001
        _fail(str(exc))
    console.print("[green]✓[/green] Removed" if r.get("removed") else "[yellow]No such rule[/yellow]")


# ---------------------------------------------------------------------------
# keylog + decrypt
# ---------------------------------------------------------------------------

_BROWSERS = {
    "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "brave": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
}


def _default_keylog() -> Path:
    return Path.home() / "Library" / "Logs" / "PyNIDS" / "sslkeys.log"


@main.command("keylog")
@click.option("--browser", type=click.Choice(sorted(_BROWSERS)), default="chrome", show_default=True)
@click.option("--file", "keylog_file", default=None, metavar="FILE", help="Key log path.")
def keylog_cmd(browser: str, keylog_file: Optional[str]) -> None:
    """Launch a browser that records its TLS session keys.

    Browsers write the per-session secrets to the file named by
    SSLKEYLOGFILE.  With it, traffic PyNIDS recorded (daemon --record) can be
    fully decrypted by `pynids decrypt` or Wireshark: full URLs, headers and
    bodies of HTTPS / HTTP-2 / HTTP-3 requests.  Safari does not support this.

    The browser opens in a separate, temporary profile so your normal
    session is untouched.  Anyone holding the key log can decrypt that
    traffic, so it is created readable only by you — delete it when done.
    """
    exe = _BROWSERS[browser]
    if not Path(exe).exists():
        _fail(f"{browser} is not installed at {exe}")
    path = Path(keylog_file) if keylog_file else _default_keylog()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)
    profile = Path.home() / "Library" / "Application Support" / "PyNIDS" / f"keylog-profile-{browser}"
    profile.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SSLKEYLOGFILE": str(path)}
    args = [exe]
    args += ["-profile", str(profile), "-no-remote"] if browser == "firefox" else [f"--user-data-dir={profile}"]
    subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    console.print(Panel(
        f"{browser.title()} launched with its own profile.\n"
        f"TLS keys → [bold]{path}[/bold]\n\n"
        "Record traffic:  sudo pynids daemon install --record   (or set record_pcap: true)\n"
        f"Decrypt:         pynids decrypt --keylog {path}",
        title="TLS key logging on", expand=False,
    ))


@main.command("decrypt")
@click.argument("pcaps", nargs=-1, type=click.Path(exists=True))
@click.option("--keylog", default=None, metavar="FILE", help="SSLKEYLOGFILE written by the browser.")
@click.option("--wireshark", is_flag=True, help="Open the capture in Wireshark with the keys loaded.")
@click.option("--limit", default=200, show_default=True)
def decrypt_cmd(pcaps, keylog: Optional[str], wireshark: bool, limit: int) -> None:
    """List decrypted HTTPS / HTTP-2 / HTTP-3 requests from recorded traffic.

    Uses the daemon's rolling capture by default and needs tshark
    (brew install --cask wireshark).
    """
    keylog_path = Path(keylog) if keylog else _default_keylog()
    if not keylog_path.exists():
        _fail(f"No key log at {keylog_path} — start a browser with: pynids keylog")
    files = [Path(p) for p in pcaps] or sorted((data_dir() / "captures").glob("*.pcap"))
    if not files:
        _fail("No recorded traffic. Enable recording: sudo pynids daemon install --record")

    if wireshark:
        subprocess.run(["open", "-a", "Wireshark", "--args", "-o",
                        f"tls.keylog_file:{keylog_path}", str(files[-1])], check=False)
        return

    tshark = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if not Path(tshark).exists():
        _fail("tshark not found — install Wireshark:  brew install --cask wireshark")

    base_fields = ["frame.time_epoch", "http.request.method", "http.host", "http.request.uri",
                   "http2.headers.method", "http2.headers.authority", "http2.headers.path"]
    h3_fields = ["http3.headers.method", "http3.headers.authority", "http3.headers.path"]

    def run_tshark(pcap: Path, fields: List[str]):
        cmd = [tshark, "-r", str(pcap), "-o", f"tls.keylog_file:{keylog_path}",
               "-Y", " or ".join(["http.request", "http2.headers.method"]
                                 + (["http3.headers.method"] if "http3.headers.method" in fields else [])),
               "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
        for fld in fields:
            cmd += ["-e", fld]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    t = Table(title=f"Decrypted requests ({len(files)} capture file(s))")
    t.add_column("Time", style="dim", no_wrap=True)
    t.add_column("Proto")
    t.add_column("Method")
    t.add_column("URL", overflow="fold")
    rows = 0
    fields = base_fields + h3_fields
    for f in files:
        proc = run_tshark(f, fields)
        if proc.returncode != 0 and fields is not base_fields and "http3" in proc.stderr:
            fields = base_fields  # this tshark build has no HTTP/3 dissector fields
            proc = run_tshark(f, fields)
        for line in proc.stdout.splitlines():
            rec = dict(zip(fields, line.split("\t")))
            if rec.get("http3.headers.method"):
                proto, method = "HTTP/3", rec["http3.headers.method"]
                url = f"https://{rec.get('http3.headers.authority', '')}{rec.get('http3.headers.path', '')}"
            elif rec.get("http2.headers.method"):
                proto, method = "HTTP/2", rec["http2.headers.method"]
                url = f"https://{rec.get('http2.headers.authority', '')}{rec.get('http2.headers.path', '')}"
            elif rec.get("http.request.method"):
                proto, method = "HTTP/1", rec["http.request.method"]
                url = f"{rec.get('http.host', '')}{rec.get('http.request.uri', '')}"
            else:
                continue
            ts = rec.get("frame.time_epoch")
            when = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S") if ts else ""
            t.add_row(when, proto, method, url)
            rows += 1
            if rows >= limit:
                break
        if rows >= limit:
            break
    if rows:
        console.print(t)
    else:
        console.print("[yellow]No decryptable requests found.[/yellow] Keys only cover traffic from the "
                      "browser launched with `pynids keylog`, captured while recording was on.")


# ---------------------------------------------------------------------------
# app (menu bar + widget)
# ---------------------------------------------------------------------------

@main.command("app")
@click.option("--install/--no-install", default=True, show_default=True,
              help="Copy the built app to ~/Applications and launch it.")
def app_cmd(install: bool) -> None:
    """Build the native menu bar app and desktop widget (needs Xcode command line tools)."""
    script = Path(__file__).resolve().parent.parent / "macos" / "build.sh"
    if not script.exists():
        _fail(f"Build script not found at {script}")
    args = ["/bin/bash", str(script)] + (["--install"] if install else [])
    sys.exit(subprocess.run(args, check=False).returncode)
