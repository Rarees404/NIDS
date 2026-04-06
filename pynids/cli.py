"""
PyNIDS command-line interface.

Built with Click and Rich for a polished, enterprise-quality terminal
experience.  All commands share the same engine-building logic.

Commands
--------
live       Real-time capture from a network interface
pcap       Replay and analyse a PCAP/PCAPNG file
query      Search persisted alerts in a SQLite database
stats      Display live engine statistics
validate   Validate a rules or configuration file
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .alerts.manager import AlertManager, BaseOutput
from .alerts.model import Alert, Severity
from .alerts.outputs.console import ConsoleOutput
from .alerts.outputs.json_file import JsonFileOutput
from .alerts.outputs.sqlite_out import SQLiteOutput
from .alerts.outputs.syslog_out import SyslogOutput
from .config import load_config
from .engine import DetectionEngine
from .intel.threat_intel import ThreatIntel
from .sniffer import sniff_live, replay_pcap

console = Console()


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="pynids")
def main() -> None:
    """
    PyNIDS — Enterprise Network Intrusion Detection System.

    Run [bold]pynids COMMAND --help[/bold] for command-specific options.
    """


# ---------------------------------------------------------------------------
# Shared option builders
# ---------------------------------------------------------------------------

_config_option = click.option(
    "--config", "-c",
    default=None,
    help="Path to YAML config file.  Defaults to configs/default.yaml.",
    metavar="FILE",
)
_rules_option = click.option(
    "--rules", "-r",
    default=None,
    help="Path to signature rules YAML file.",
    metavar="FILE",
)
_output_option = click.option(
    "--output", "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Alert output format for console.",
)
_severity_option = click.option(
    "--min-severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Minimum severity level to display.",
)
_verbose_option = click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Show evidence fields for each alert.",
)


def _resolve_config(config: Optional[str]) -> str:
    """Return config path, defaulting to configs/default.yaml."""
    if config:
        return config
    default = Path("configs/default.yaml")
    if default.exists():
        return str(default)
    # Fall back to a minimal inline config
    return "__default__"


class _JsonStdout(BaseOutput):
    """Write each alert as a JSON line to stdout."""

    def emit(self, alert: Alert) -> None:
        sys.stdout.write(json.dumps(alert.to_dict()) + "\n")
        sys.stdout.flush()


def _build_engine(
    config_path: str,
    rules_path: Optional[str],
    min_severity: str,
    show_evidence: bool,
    json_output: bool,
    sqlite_path: Optional[str] = None,
) -> DetectionEngine:
    """Construct the full engine + alert manager from CLI options."""
    # Load config
    if config_path == "__default__":
        cfg: dict = {}
    else:
        try:
            cfg = load_config(config_path)
        except FileNotFoundError:
            console.print(f"[red]Config file not found: {config_path}[/red]")
            sys.exit(1)

    # Build alert manager
    am_cfg = cfg.get("alert_manager", {})
    mgr = AlertManager(
        dedup_window=float(am_cfg.get("dedup_window", 60)),
        correlation_window=float(am_cfg.get("correlation_window", 120)),
        correlation_threshold=int(am_cfg.get("correlation_threshold", 3)),
        min_severity=Severity(min_severity),
        suppression_rules=am_cfg.get("suppression", []),
    )

    # Console / JSON stdout output
    out_cfg = cfg.get("outputs", {})
    if not json_output:
        con_cfg = out_cfg.get("console", {})
        mgr.register_output(
            ConsoleOutput(
                min_severity=Severity(min_severity),
                show_evidence=show_evidence or bool(con_cfg.get("show_evidence", False)),
            )
        )
    else:
        mgr.register_output(_JsonStdout())

    # SQLite — CLI flag takes precedence, then config
    effective_sqlite = sqlite_path
    if not effective_sqlite:
        sq_cfg = out_cfg.get("sqlite", {})
        if sq_cfg.get("enabled"):
            effective_sqlite = sq_cfg.get("path", "pynids-alerts.db")
    if effective_sqlite:
        mgr.register_output(SQLiteOutput(path=effective_sqlite))

    # JSON file from config
    jf_cfg = out_cfg.get("json_file", {})
    if jf_cfg.get("enabled"):
        mgr.register_output(
            JsonFileOutput(
                path=jf_cfg.get("path", "pynids-alerts.json"),
                max_bytes=int(jf_cfg.get("max_bytes", 10 * 1024 * 1024)),
                backup_count=int(jf_cfg.get("backup_count", 5)),
            )
        )

    # Syslog from config
    sl_cfg = out_cfg.get("syslog", {})
    if sl_cfg.get("enabled"):
        mgr.register_output(
            SyslogOutput(
                host=sl_cfg.get("host", "localhost"),
                port=int(sl_cfg.get("port", 514)),
                protocol=sl_cfg.get("protocol", "udp"),
                min_severity=Severity(min_severity),
            )
        )

    # Threat intelligence
    intel_cfg = cfg.get("intel", {})
    intel = None
    if intel_cfg.get("enabled"):
        intel = ThreatIntel(
            bad_ips_path=intel_cfg.get("bad_ips_file"),
            malicious_domains_path=intel_cfg.get("malicious_domains_file"),
        )

    return DetectionEngine(
        config=cfg,
        rules_path=rules_path,
        intel=intel,
        alert_manager=mgr,
    )


# ---------------------------------------------------------------------------
# live command
# ---------------------------------------------------------------------------

@main.command()
@click.option("--iface", "-i", required=True, help="Network interface (e.g. en0, eth0).")
@click.option("--bpf", default=None, help="BPF capture filter (e.g. 'tcp port 80').")
@click.option("--sqlite", default=None, help="Persist alerts to this SQLite file.", metavar="FILE")
@click.option(
    "--reload-interval",
    default=30,
    show_default=True,
    type=int,
    help="Check for rules file changes every N seconds (0 = disable hot-reload).",
)
@_config_option
@_rules_option
@_output_option
@_severity_option
@_verbose_option
def live(
    iface: str,
    bpf: Optional[str],
    sqlite: Optional[str],
    reload_interval: int,
    config: Optional[str],
    rules: Optional[str],
    output: str,
    min_severity: str,
    verbose: bool,
) -> None:
    """Capture and analyse live traffic from a network interface.

    Requires root/administrator privileges.

    \b
    Examples:
      pynids live --iface en0 --rules rules/enterprise_rules.yaml
      pynids live --iface eth0 --bpf "not port 22" --sqlite alerts.db
      pynids live --iface eth0 --rules rules/enterprise_rules.yaml --reload-interval 15
    """
    config_path = _resolve_config(config)
    engine = _build_engine(
        config_path, rules, min_severity, verbose,
        json_output=(output == "json"), sqlite_path=sqlite
    )
    _print_banner(iface=iface, rules=rules, config=config_path)

    # Hot-reload background watcher
    _stop_event = threading.Event()
    if rules and reload_interval > 0:
        def _watcher() -> None:
            while not _stop_event.wait(timeout=reload_interval):
                if engine.reload_rules():
                    console.print(
                        f"[dim][{time.strftime('%H:%M:%S')}] Rules hot-reloaded from "
                        f"{rules}[/dim]"
                    )

        watcher_thread = threading.Thread(target=_watcher, daemon=True, name="rules-watcher")
        watcher_thread.start()

    try:
        sniff_live(iface=iface, engine_callback=engine.process_packet, bpf_filter=bpf)
    finally:
        _stop_event.set()
        engine.alert_manager.close()
        _print_stats(engine)


# ---------------------------------------------------------------------------
# pcap command
# ---------------------------------------------------------------------------

@main.command()
@click.option("--file", "-f", "pcap_file", required=True, help="Path to PCAP/PCAPNG file.")
@click.option("--sqlite", default=None, help="Persist alerts to this SQLite file.", metavar="FILE")
@_config_option
@_rules_option
@_output_option
@_severity_option
@_verbose_option
def pcap(
    pcap_file: str,
    sqlite: Optional[str],
    config: Optional[str],
    rules: Optional[str],
    output: str,
    min_severity: str,
    verbose: bool,
) -> None:
    """Analyse packets from a PCAP or PCAPNG capture file.

    \b
    Examples:
      pynids pcap --file capture.pcap --rules rules/enterprise_rules.yaml
      pynids pcap --file sample.pcap --output json | jq 'select(.severity=="HIGH")'
    """
    if not Path(pcap_file).exists():
        console.print(f"[red]PCAP file not found: {pcap_file}[/red]")
        sys.exit(1)

    config_path = _resolve_config(config)
    engine = _build_engine(
        config_path, rules, min_severity, verbose,
        json_output=(output == "json"), sqlite_path=sqlite
    )

    start = time.time()
    try:
        count = replay_pcap(pcap_path=pcap_file, engine_callback=engine.process_packet)
    finally:
        engine.alert_manager.close()

    elapsed = time.time() - start
    if output == "text":
        console.print(
            f"\n[dim]Processed [bold]{count}[/bold] packets in {elapsed:.2f}s "
            f"({count / max(elapsed, 0.001):.0f} pkt/s)[/dim]"
        )
        _print_stats(engine)


# ---------------------------------------------------------------------------
# query command
# ---------------------------------------------------------------------------

@main.command()
@click.option("--db", required=True, help="Path to SQLite alerts database.", metavar="FILE")
@click.option("--min-severity", default="LOW", type=click.Choice(["LOW","MEDIUM","HIGH","CRITICAL"]))
@click.option("--src-ip", default=None, help="Filter by source IP address.")
@click.option("--type", "alert_type", default=None,
              type=click.Choice(["signature","anomaly","behavioral","threat_intel","correlation"]))
@click.option("--limit", default=50, show_default=True, help="Maximum rows to return.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON lines.")
def query(
    db: str,
    min_severity: str,
    src_ip: Optional[str],
    alert_type: Optional[str],
    limit: int,
    as_json: bool,
) -> None:
    """Query alerts stored in a SQLite database.

    \b
    Examples:
      pynids query --db alerts.db --min-severity HIGH
      pynids query --db alerts.db --src-ip 10.0.0.5 --json
    """
    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    store = SQLiteOutput(path=db)
    rows = store.query(
        min_severity=min_severity,
        src_ip=src_ip,
        alert_type=alert_type,
        limit=limit,
    )
    store.close()

    if not rows:
        console.print("[dim]No alerts found.[/dim]")
        return

    if as_json:
        for row in rows:
            print(json.dumps(row))
        return

    table = Table(title=f"Alerts ({len(rows)} rows)", show_lines=False)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Message")
    table.add_column("MITRE", style="dim")

    _sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
    }
    from datetime import datetime
    for row in rows:
        ts = datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        sev = row.get("severity", "")
        src = row.get("src_ip") or "-"
        dst = (row.get("dst_ip") or "-") + (":" + str(row["dst_port"]) if row.get("dst_port") else "")
        table.add_row(
            ts,
            Text(sev, style=_sev_colors.get(sev, "")),
            row.get("alert_type", ""),
            src,
            dst,
            (row.get("message") or "")[:80],
            row.get("mitre_technique") or "",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# stats command
# ---------------------------------------------------------------------------

@main.command()
@click.option("--db", default=None, help="Path to SQLite alerts database for aggregate stats.", metavar="FILE")
@click.option("--json", "as_json", is_flag=True, help="Output stats as JSON.")
def stats(db: Optional[str], as_json: bool) -> None:
    """Display aggregate alert statistics from a SQLite database.

    \b
    Examples:
      pynids stats --db alerts.db
      pynids stats --db alerts.db --json
    """
    if not db:
        console.print("[red]--db is required for the stats command.[/red]")
        sys.exit(1)
    if not Path(db).exists():
        console.print(f"[red]Database not found: {db}[/red]")
        sys.exit(1)

    import sqlite3
    conn = sqlite3.connect(db)
    cur = conn.cursor()

    # Total counts
    cur.execute("SELECT COUNT(*) FROM alerts")
    total = cur.fetchone()[0]

    # By severity
    cur.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY severity_numeric DESC"
    )
    by_severity = dict(cur.fetchall())

    # By type
    cur.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type ORDER BY COUNT(*) DESC")
    by_type = dict(cur.fetchall())

    # Top 10 source IPs
    cur.execute(
        "SELECT src_ip, COUNT(*) as cnt FROM alerts WHERE src_ip IS NOT NULL "
        "GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
    )
    top_sources = cur.fetchall()

    # Top MITRE techniques
    cur.execute(
        "SELECT mitre_technique, COUNT(*) as cnt FROM alerts WHERE mitre_technique IS NOT NULL "
        "GROUP BY mitre_technique ORDER BY cnt DESC LIMIT 10"
    )
    top_mitre = cur.fetchall()

    # Time range
    cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts")
    ts_min, ts_max = cur.fetchone()
    conn.close()

    if as_json:
        from datetime import datetime
        output_data = {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "top_source_ips": [{"ip": r[0], "count": r[1]} for r in top_sources],
            "top_mitre_techniques": [{"technique": r[0], "count": r[1]} for r in top_mitre],
            "time_range": {
                "earliest": datetime.fromtimestamp(ts_min).isoformat() if ts_min else None,
                "latest": datetime.fromtimestamp(ts_max).isoformat() if ts_max else None,
            },
        }
        print(json.dumps(output_data, indent=2))
        return

    from datetime import datetime

    console.print(Panel(
        f"[bold cyan]PyNIDS Alert Statistics[/bold cyan]\n"
        f"Database: [dim]{db}[/dim]",
        expand=False,
    ))

    # Summary table
    summary = Table(title="Summary", show_header=False, box=None)
    summary.add_column("Key", style="dim")
    summary.add_column("Value", style="bold")
    summary.add_row("Total alerts", str(total))
    if ts_min and ts_max:
        summary.add_row("Earliest", datetime.fromtimestamp(ts_min).strftime("%Y-%m-%d %H:%M:%S"))
        summary.add_row("Latest", datetime.fromtimestamp(ts_max).strftime("%Y-%m-%d %H:%M:%S"))
    console.print(summary)

    # Severity breakdown
    sev_table = Table(title="By Severity")
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    _sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = by_severity.get(sev, 0)
        if cnt:
            sev_table.add_row(Text(sev, style=_sev_colors.get(sev, "")), str(cnt))
    console.print(sev_table)

    # Type breakdown
    type_table = Table(title="By Detection Type")
    type_table.add_column("Type")
    type_table.add_column("Count", justify="right")
    for t, cnt in by_type.items():
        type_table.add_row(t, str(cnt))
    console.print(type_table)

    # Top sources
    if top_sources:
        src_table = Table(title="Top Source IPs")
        src_table.add_column("IP")
        src_table.add_column("Alerts", justify="right")
        for ip, cnt in top_sources:
            src_table.add_row(ip or "-", str(cnt))
        console.print(src_table)

    # Top MITRE techniques
    if top_mitre:
        mitre_table = Table(title="Top MITRE Techniques")
        mitre_table.add_column("Technique")
        mitre_table.add_column("Count", justify="right")
        for technique, cnt in top_mitre:
            mitre_table.add_row(technique, str(cnt))
        console.print(mitre_table)


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--type", "file_type",
              type=click.Choice(["rules", "config", "auto"]),
              default="auto")
def validate(file: str, file_type: str) -> None:
    """Validate a rules or configuration YAML file.

    \b
    Examples:
      pynids validate rules/enterprise_rules.yaml
      pynids validate configs/enterprise.yaml --type config
    """
    import yaml as _yaml
    from .detection.signature import load_rules as _load_rules

    try:
        with open(file, encoding="utf-8") as f:
            data = _yaml.safe_load(f)
    except _yaml.YAMLError as exc:
        console.print(f"[red]YAML parse error:[/red] {exc}")
        sys.exit(1)

    # Auto-detect
    if file_type == "auto":
        file_type = "rules" if "rules" in (data or {}) else "config"

    if file_type == "rules":
        rules = (data or {}).get("rules", [])
        errors = 0
        for i, rule in enumerate(rules):
            if "id" not in rule:
                console.print(f"[yellow]Rule #{i}: missing 'id'[/yellow]")
                errors += 1
            if "match" not in rule:
                console.print(f"[yellow]Rule {rule.get('id', f'#{i}')}: missing 'match'[/yellow]")
                errors += 1
            sev = rule.get("severity", "MEDIUM").upper()
            if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                console.print(f"[yellow]Rule {rule.get('id')}: invalid severity '{sev}'[/yellow]")
                errors += 1
        if errors == 0:
            console.print(f"[green]✓ {len(rules)} rules validated — no errors[/green]")
        else:
            console.print(f"[red]{errors} error(s) found in {len(rules)} rules[/red]")
            sys.exit(1)
    else:
        console.print(f"[green]✓ Config YAML is valid ({len(data or {})} top-level keys)[/green]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_banner(iface: Optional[str] = None, rules: Optional[str] = None,
                  config: Optional[str] = None) -> None:
    lines = [
        f"[bold cyan]PyNIDS[/bold cyan] v{__version__} — Enterprise NIDS",
    ]
    if iface:
        lines.append(f"Interface : [bold]{iface}[/bold]")
    if rules:
        lines.append(f"Rules     : [bold]{rules}[/bold]")
    if config and config != "__default__":
        lines.append(f"Config    : [bold]{config}[/bold]")
    lines.append("[dim]Press Ctrl+C to stop[/dim]")
    console.print(Panel("\n".join(lines), expand=False))


def _print_stats(engine: DetectionEngine) -> None:
    s = engine.stats
    am = s.get("alert_stats", {})
    table = Table(title="Session Statistics", show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value", style="bold")
    table.add_row("Packets processed", str(s["packets_processed"]))
    table.add_row("Throughput", f"{s['packets_per_second']} pkt/s")
    table.add_row("Active flows", str(s["active_flows"]))
    table.add_row("Uptime", f"{s['uptime_seconds']:.1f}s")
    table.add_row("Alerts seen", str(am.get("total_seen", 0)))
    table.add_row("Alerts emitted", str(am.get("total_emitted", 0)))
    table.add_row("Deduplicated", str(am.get("total_deduplicated", 0)))
    table.add_row("Suppressed", str(am.get("total_suppressed", 0)))
    console.print(table)
