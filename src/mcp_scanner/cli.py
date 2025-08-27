from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from .models import Report
from .scanner import scan_server


console = Console()


@click.group()
def main() -> None:
    """MCP Security Scanner CLI."""


@main.command("scan")
@click.option("--url", required=True, help="Target MCP server websocket URL (ws:// or wss://)")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", type=click.Path(dir_okay=False), help="Write report to file")
def scan_cmd(url: str, spec: Optional[str], fmt: str, output: Optional[str]) -> None:
    report: Report = scan_server(url, spec_path=spec)
    if fmt == "json":
        data = report.model_dump()
        out = json.dumps(data, indent=2)
        if output:
            Path(output).write_text(out)
            console.print(f"Wrote JSON report to {output}")
        else:
            console.print(out)
    else:
        table = Table(title=f"MCP Security Scan: {report.target}")
        table.add_column("ID")
        table.add_column("Title")
        table.add_column("Severity")
        table.add_column("Pass")
        table.add_column("Details")
        for f in report.findings:
            table.add_row(f.id, f.title, f.severity.value, "✅" if f.passed else "❌", (f.details[:120] + "...") if len(f.details) > 120 else f.details)
        console.print(table)
        console.print(f"Summary: {report.summary}")


