"""
Rich console output backend for PyNIDS.

Renders alerts as a colour-coded table using the ``rich`` library.
Severity levels map to distinct terminal colours for fast visual triage:

    CRITICAL → bold red on dark-red background
    HIGH     → bold red
    MEDIUM   → bold yellow
    LOW      → cyan
"""
from __future__ import annotations

import time
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..manager import BaseOutput
from ..model import Alert, Severity

_SEVERITY_STYLE: dict = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
}

_TYPE_STYLE: dict = {
    "signature": "bright_magenta",
    "anomaly": "bright_yellow",
    "behavioral": "bright_cyan",
    "threat_intel": "bright_red",
    "correlation": "bold bright_red",
}


class ConsoleOutput(BaseOutput):
    """
    Write each alert to the terminal using rich formatting.

    Args:
        min_severity: Only display alerts at or above this level.
        show_evidence: Include evidence dict in the output (verbose mode).
        console:      Inject a :class:`rich.console.Console` instance
                      (useful for testing / redirected output).
    """

    def __init__(
        self,
        min_severity: Severity = Severity.LOW,
        show_evidence: bool = False,
        console: Console | None = None,
    ) -> None:
        self.min_severity = min_severity
        self.show_evidence = show_evidence
        self._console = console or Console(highlight=False)

    def emit(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return

        ts = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S.%f")[:-3]
        sev_style = _SEVERITY_STYLE.get(alert.severity, "white")
        type_style = _TYPE_STYLE.get(alert.alert_type.value, "white")

        sev_text = Text(f" {alert.severity.value:<8} ", style=sev_style)
        type_text = Text(f"{alert.alert_type.value:<11}", style=type_style)

        src = f"{alert.src_ip}" + (f":{alert.src_port}" if alert.src_port else "")
        dst = (
            (f"{alert.dst_ip}" + (f":{alert.dst_port}" if alert.dst_port else ""))
            if alert.dst_ip
            else "-"
        )

        mitre = f"[dim][{alert.mitre_technique}][/dim] " if alert.mitre_technique else ""
        tags = f"[dim]({', '.join(alert.tags)})[/dim]" if alert.tags else ""

        self._console.print(
            f"[dim]{ts}[/dim] ",
            sev_text,
            " ",
            type_text,
            f" [bold]{src}[/bold] → [bold]{dst}[/bold]  ",
            mitre,
            f"{alert.message}  ",
            tags,
            sep="",
        )

        if self.show_evidence and alert.evidence:
            for k, v in alert.evidence.items():
                if isinstance(v, (list, dict)):
                    self._console.print(f"  [dim]  {k}: {v}[/dim]")
                elif v is not None:
                    self._console.print(f"  [dim]  {k}: {v}[/dim]")
