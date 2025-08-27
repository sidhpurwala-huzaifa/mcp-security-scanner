from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from .models import Report
from .scanner import scan_server
from .spec import load_spec
from .http_checks import scan_http_base
from .sse_scanner import run_checks_sse


console = Console()


@click.group()
def main() -> None:
    """MCP Security Scanner CLI."""


@main.command("scan")
@click.option("--url", required=True, help="Target MCP server websocket URL (ws:// or wss://)")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--transport", type=click.Choice(["ws", "sse"]), default="ws")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
@click.option("--output", type=click.Path(dir_okay=False), help="Write report to file")
def scan_cmd(url: str, spec: Optional[str], fmt: str, transport: str, verbose: bool, output: Optional[str]) -> None:
    trace: list[dict] = [] if verbose else []
    if transport == "ws":
        report: Report = scan_server(url, spec_path=spec, verbose=verbose, trace=trace)
    else:
        from .spec import load_spec
        from .models import Report
        from pathlib import Path

        spec_file = Path(spec) if spec else Path(__file__).resolve().parents[2] / "scanner_specs.schema"
        spec_index = load_spec(spec_file)
        findings = run_checks_sse(url, spec_index, trace=trace, verbose=verbose)
        report = Report.new(target=url, findings=findings)
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
        if verbose and trace:
            console.rule("Trace")
            for entry in trace:
                console.print(entry)


@main.command("scan-range")
@click.option("--host", required=True, help="Target host, e.g., localhost")
@click.option("--ports", required=True, help="Comma or dash separated ports, e.g., 9001-9010 or 8765,9001")
@click.option("--scheme", type=click.Choice(["ws", "wss", "http", "https", "sse"]), default="http")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
def scan_range_cmd(host: str, ports: str, scheme: str, spec: Optional[str], verbose: bool) -> None:
    spec_file = spec
    if spec_file is None:
        from pathlib import Path

        spec_file = str(Path(__file__).resolve().parents[2] / "scanner_specs.schema")
    spec_index = load_spec(Path(spec_file))
    ports_list: list[int] = []
    for part in ports.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            ports_list.extend(range(int(a), int(b) + 1))
        else:
            ports_list.append(int(part))

    table = Table(title=f"Scan range {scheme} on {host}:{ports}")
    table.add_column("Target")
    table.add_column("Findings summary")
    for p in ports_list:
        trace: list[dict] = [] if verbose else []
        if scheme in ("ws", "wss"):
            target = f"{scheme}://{host}:{p}"
            report = scan_server(target, spec_path=spec_file, verbose=verbose, trace=trace)
            table.add_row(target, str(report.summary))
        elif scheme in ("http", "https"):
            base = f"{scheme}://{host}:{p}"
            findings = scan_http_base(base, spec_index)
            # Build a mini summary
            passed = sum(1 for f in findings if f.passed)
            failed = sum(1 for f in findings if not f.passed)
            table.add_row(base, f"passed={passed} failed={failed}")
        else:  # sse
            base = f"http://{host}:{p}"
            findings = run_checks_sse(base, spec_index, trace=trace, verbose=verbose)
            passed = sum(1 for f in findings if f.passed)
            failed = sum(1 for f in findings if not f.passed)
            table.add_row(base + "/sse", f"passed={passed} failed={failed}")
    console.print(table)


