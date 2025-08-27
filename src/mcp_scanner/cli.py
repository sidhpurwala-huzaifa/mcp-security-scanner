from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from .models import Report
from .spec import load_spec
from .http_checks import run_full_http_checks, scan_http_base
from .auth import build_auth_headers


console = Console()


@click.group()
def main() -> None:
    """MCP Security Scanner CLI (HTTP-only)."""


@main.command("scan")
@click.option("--url", required=True, help="Target MCP server base URL (http:// or https://)")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
@click.option("--explain", is_flag=True, default=False, help="Plain-English summary of sent/received/expected and exploited capability")
@click.option("--auth-type", type=click.Choice(["bearer", "oauth2-client-credentials"]))
@click.option("--auth-token")
@click.option("--token-url")
@click.option("--client-id")
@click.option("--client-secret")
@click.option("--scope")
@click.option("--output", type=click.Path(dir_okay=False), help="Write report to file")
def scan_cmd(url: str, spec: Optional[str], fmt: str, verbose: bool, explain: bool, auth_type: Optional[str], auth_token: Optional[str], token_url: Optional[str], client_id: Optional[str], client_secret: Optional[str], scope: Optional[str], output: Optional[str]) -> None:
    if verbose and explain:
        console.print("--verbose and --explain are mutually exclusive; using --explain.")
        verbose = False
    trace: list[dict] = [] if (verbose or explain) else []
    auth_headers = build_auth_headers(auth_type, auth_token, token_url, client_id, client_secret, scope)

    spec_file = Path(spec) if spec else Path(__file__).resolve().parents[2] / "scanner_specs.schema"
    spec_index = load_spec(spec_file)

    findings = run_full_http_checks(url, spec_index, headers=auth_headers, trace=trace, verbose=verbose)
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
        if explain:
            console.rule("Explanation")
            for line in _explain_findings(report, trace):
                console.print(f"- {line}")


@main.command("scan-range")
@click.option("--host", required=True, help="Target host, e.g., localhost")
@click.option("--ports", required=True, help="Comma or dash separated ports, e.g., 9001-9010 or 8765,9001")
@click.option("--scheme", type=click.Choice(["http", "https"]), default="http")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
@click.option("--explain", is_flag=True, default=False, help="Plain-English summary of sent/received/expected and exploited capability")
def scan_range_cmd(host: str, ports: str, scheme: str, spec: Optional[str], verbose: bool, explain: bool) -> None:
    spec_file = spec
    if spec_file is None:
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
        trace: list[dict] = [] if (verbose or explain) else []
        base = f"{scheme}://{host}:{p}"
        findings = run_full_http_checks(base, spec_index, trace=trace, verbose=verbose)
        passed = sum(1 for f in findings if f.passed)
        failed = sum(1 for f in findings if not f.passed)
        table.add_row(base, f"passed={passed} failed={failed}")
    console.print(table)
    if explain:
        console.rule("Explanation")
        console.print("Re-run single-target scan with --explain for detailed narrative.")


def _explain_findings(report: Report, trace: list[dict]) -> list[str]:
    explanations: list[str] = []
    # index first send/recv by method for reference
    first_send: dict[str, dict] = {}
    first_recv: dict[str, dict] = {}
    for entry in trace:
        if entry.get("direction") == "send":
            req = entry.get("request") or {}
            method = req.get("method")
            if method and method not in first_send:
                first_send[method] = req
        elif entry.get("direction") == "recv":
            data = entry.get("data") or entry.get("raw")
            # Cannot reliably map to method; store generically
            if isinstance(data, dict):
                method = data.get("result", {}).get("method") or data.get("method")
                if method and method not in first_recv:
                    first_recv[method] = data
    for f in report.findings:
        sent = ""
        received = ""
        expected = ""
        exploited = f.title
        if f.id == "A-01":
            sent = "Called tools/list without auth"
            received = "Server returned tool list"
            expected = "401 or denial when unauthenticated"
        elif f.id == "T-02":
            sent = "Checked scheme"
            received = f.details
            expected = "HTTPS/WSS with HSTS"
        elif f.id == "X-01":
            sent = "Parsed tools/list and schemas"
            received = "Found high-risk tool(s) lacking constraints" if not f.passed else "No risky unconstrained tools"
            expected = "Destructive tools should be gated and constrained"
        elif f.id == "P-02":
            sent = "Scanned tool descriptions"
            received = "Detected manipulative hidden instructions" if not f.passed else "No injection-style instructions"
            expected = "Descriptions free of meta-instructions"
        elif f.id == "X-03":
            sent = "Listed tools twice"
            received = "Descriptions/names changed between listings" if not f.passed else "No changes detected"
            expected = "Stable, versioned tool metadata"
        elif f.id == "R-01":
            sent = "resources/read with ../../ path traversal"
            received = "Traversal accepted" if not f.passed else "Traversal blocked"
            expected = "Reject escaped/invalid URIs"
        elif f.id == "R-03":
            sent = "Listed resources and read sensitive URIs"
            received = "Secrets or credentials present" if not f.passed else "No sensitive exposure"
            expected = "Do not list/read internal credentials"
        elif f.id == "R-04":
            sent = "Probed uriTemplate with crafted values"
            received = "Unconstrained template reflected/leaked data" if not f.passed else "Templates constrained/blocked"
            expected = "Validate inputs and constrain templates"
        elif f.id == "R-05":
            sent = "Read private:// resources"
            received = "Private data readable" if not f.passed else "Private namespaces not readable"
            expected = "Enforce RBAC and hide private namespaces"
        else:
            sent = "Performed check"
            received = "See details"
            expected = "Per spec"
        status = "FAILED" if not f.passed else "PASSED"
        explanations.append(
            f"{f.id} ({status}): Sent: {sent}. Received: {received}. Expected: {expected}. Exploited: {exploited}."
        )
    return explanations


