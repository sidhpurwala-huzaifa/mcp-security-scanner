from __future__ import annotations

from pathlib import Path
import json
import sys
from typing import Optional, Any, Dict, Iterator, List

import click
from rich.console import Console
from rich.table import Table

from .models import Report
from .spec import load_spec
from .http_checks import run_full_http_checks, scan_http_base, get_server_health, rpc_call
from .stdio_scanner import scan_stdio, get_stdio_health
from .auth import build_auth_headers
import httpx


console = Console()


@click.group()
def main() -> None:
    """MCP Security Scanner CLI."""


@main.command("scan")
@click.option("--url", help="Target MCP server base URL (http:// or https://), not required for stdio transport")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
@click.option("--explain", "explain_id", help="Explain a specific finding by ID (e.g., X-01)")
@click.option("--transport", type=click.Choice(["auto", "http", "sse", "stdio"]), default="auto", show_default=True, help="Preferred transport hint; auto tries SSE when available")
@click.option("--only-health", is_flag=True, default=False, help="Dump endpoints, tools, prompts, resources and exit (no scan)")
@click.option("--sse-endpoint", help="When --transport sse, append this path to --url for SSE (e.g., /sse)")
@click.option("--auth-type", type=click.Choice(["bearer", "oauth2-client-credentials"]))
@click.option("--auth-token")
@click.option("--token-url")
@click.option("--client-id")
@click.option("--client-secret")
@click.option("--scope")
@click.option("--output", type=click.Path(dir_okay=False), help="Write report to file")
@click.option("--timeout", type=float, default=12.0, show_default=True, help="Per-request read timeout in seconds")
@click.option("--session-id", help="Pre-supplied session id to include in Mcp-Session-Id header")
@click.option("--command", help="Command to run MCP server (required for stdio transport)")
def scan_cmd(url: str, spec: Optional[str], fmt: str, verbose: bool, explain_id: Optional[str], auth_type: Optional[str], auth_token: Optional[str], token_url: Optional[str], client_id: Optional[str], client_secret: Optional[str], scope: Optional[str], output: Optional[str], timeout: float, session_id: Optional[str], transport: str, only_health: bool, sse_endpoint: Optional[str], command: Optional[str]) -> None:
    if verbose and explain_id:
        console.print("--verbose and --explain are mutually exclusive; using --explain.")
        verbose = False

    # Validate stdio transport requirements
    if transport == "stdio":
        if not command:
            raise click.ClickException("--command is required when using --transport stdio")
        if url and url != "stdio://command":
            console.print("Note: --url is ignored when using stdio transport, using provided --command instead")
    else:
        if not url:
            raise click.ClickException("--url is required when not using stdio transport")
        if command:
            raise click.ClickException("--command can only be used with --transport stdio")

    if transport == "sse":
        console.print("SSE is deprecated in MCP!!! SSE support in the scanner is experimental and may not work!!!")
    class RealtimeTrace:
        def __init__(self, c: Console) -> None:
            self._c = c
            self._store: List[Dict[str, Any]] = []

        def _truncate(self, value: str, limit: int = 500) -> str:
            return value if len(value) <= limit else (value[:limit] + "...")

        def append(self, entry: Dict[str, Any]) -> None:  # type: ignore[override]
            self._store.append(entry)
            direction = entry.get("direction")
            note = entry.get("note")
            if direction == "send":
                if isinstance(entry.get("request"), dict):
                    req = entry["request"]
                    rpc_method = req.get("method")
                    url_s = entry.get("url", "")
                    body = self._truncate(json.dumps(req))
                    line = f"Sent RPC {rpc_method} -> {url_s} body={body}"
                else:
                    method = entry.get("method", "")
                    url_s = entry.get("url", "")
                    hdrs = entry.get("headers")
                    hstr = f" headers={hdrs}" if hdrs else ""
                    line = f"Sent {method} {url_s}{hstr}"
                if note:
                    line += f" note={note}"
                self._c.print(line)
            elif direction == "recv":
                status = entry.get("status")
                data = entry.get("data")
                if isinstance(data, (dict, list)):
                    body = self._truncate(json.dumps(data))
                elif isinstance(data, str):
                    body = self._truncate(data)
                else:
                    body = self._truncate(str(entry.get("raw") or ""))
                line = f"Received status={status} body={body}"
                if note:
                    line += f" note={note}"
                self._c.print(line)
            elif direction == "error":
                self._c.print(f"Error: {entry.get('error')}")
            elif direction == "info":
                info = {k: v for k, v in entry.items() if k not in ("transport", "direction")}
                self._c.print(f"Info: {info}")

        def __iter__(self) -> Iterator[Dict[str, Any]]:
            return iter(self._store)

    # Collect a trace for explanation mode; use realtime only in verbose
    trace: Any = RealtimeTrace(console) if verbose else ([] if explain_id else [])
    auth_headers = build_auth_headers(auth_type, auth_token, token_url, client_id, client_secret, scope)
    if session_id:
        auth_headers = {**auth_headers, "Mcp-Session-Id": session_id}

    # Preflight reachability check for HTTP/HTTPS transports only
    if transport != "stdio":
        if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
            raise click.ClickException("--url must start with http:// or https://")
        try:
            with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout)) as _c:
                _c.get(url, timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout))
        except httpx.RequestError as e:  # noqa: PERF203
            raise click.ClickException(f"Cannot reach MCP server at {url}: {type(e).__name__}: {e}")

    spec_file = Path(spec) if spec else None
    if spec_file is not None:
        spec_index = load_spec(spec_file)
    else:
        spec_index = load_spec()

    # Transport hint is advisory; the checker auto-handles SSE vs JSON responses based on Content-Type
    if transport == "sse" and "Accept" not in auth_headers:
        auth_headers = {**auth_headers, "Accept": "application/json, text/event-stream"}
    elif transport == "http" and "Accept" not in auth_headers:
        auth_headers = {**auth_headers, "Accept": "application/json, text/event-stream"}
    if only_health:
        if transport == "stdio":
            health = get_stdio_health(command)
        else:
            health = get_server_health(url, headers=auth_headers, trace=trace, verbose=verbose, timeout=timeout, transport=transport, sse_endpoint=sse_endpoint)
        if fmt == "json":
            console.rule("Health (JSON)")
            console.print_json(json.dumps(health))
            return
        # Text output
        console.rule("Health")

        # Handle stdio vs HTTP health data
        if transport == "stdio":
            target = health.get("target", "stdio")
            console.print(f"Target: {target}")
            console.print(f"Transport: {health.get('transport', 'stdio')}")
            if "error" in health:
                console.print(f"[red]Error: {health['error']}[/red]")
        else:
            base = health.get("base_url")
            msg_url = health.get("msg_url")
            sse_url = health.get("sse_url")
            console.print(f"Base URL: {base}")
            console.print(f"Message endpoint: {msg_url}")
            console.print(f"SSE URL: {sse_url}")

        init_obj = health.get("initialize") or {}
        tools = health.get("tools") or []
        prompts = health.get("prompts") or []
        resources = health.get("resources") or []
        if isinstance(init_obj, dict):
            keys = list((init_obj.get("result") or {}).keys()) if "result" in init_obj else list(init_obj.keys())
            console.print(f"Initialize keys: {keys}")
        # Tools table
        ttable = Table(title="Tools")
        ttable.add_column("Name")
        ttable.add_column("Description")
        if tools:
            for t in tools:
                ttable.add_row(str(t.get("name", "")), (t.get("description") or ""))
        else:
            ttable.add_row("-", "No tools discovered")
        console.print(ttable)
        # Prompts table
        ptable = Table(title="Prompts")
        ptable.add_column("Name")
        ptable.add_column("Required")
        if prompts:
            for p in prompts:
                req = ",".join(p.get("inputSchema", {}).get("required", []) if isinstance(p.get("inputSchema"), dict) else [])
                ptable.add_row(str(p.get("name", "")), req)
        else:
            ptable.add_row("-", "No prompts discovered")
        console.print(ptable)
        # Resources table
        rtable = Table(title="Resources")
        rtable.add_column("Name")
        rtable.add_column("URI")
        rtable.add_column("Template")
        if resources:
            for r in resources:
                rtable.add_row(str(r.get("name", "")), str(r.get("uri", "")), str(r.get("uriTemplate", "")))
        else:
            rtable.add_row("-", "No resources discovered", "")
        console.print(rtable)
        return

    # Run scanning based on transport type
    if transport == "stdio":
        report = scan_stdio(command, spec_index)
    else:
        findings = run_full_http_checks(url, spec_index, headers=auth_headers, trace=trace, verbose=verbose, timeout=timeout, transport=transport, sse_endpoint=sse_endpoint)
        report = Report.new(target=url, findings=findings)

    if only_health:
        return
    if fmt == "json":
        out = report.model_dump_json(indent=2)
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
        if explain_id:
            console.rule(f"Explanation for {explain_id}")
            f = next((x for x in report.findings if x.id == explain_id), None)
            if not f:
                console.print(f"Finding {explain_id} not found in this report.")
            else:
                for line in _explain_single(f, spec_index, list(trace) if isinstance(trace, list) else []):
                    console.print(f"- {line}")
    failed = [f for f in report.findings if not f.passed]
    if failed:
        console.print(f"[red]Scan failed: {len(failed)} findings[/red]")
        sys.exit(1)
    else:
        console.print("[green]All checks passed[/green]")
        sys.exit(0)

@main.command("scan-range")
@click.option("--host", required=True, help="Target host, e.g., localhost")
@click.option("--ports", required=True, help="Comma or dash separated ports, e.g., 9001-9010 or 8765,9001")
@click.option("--scheme", type=click.Choice(["http", "https"]), default="http")
@click.option("--spec", type=click.Path(exists=True, dir_okay=False), help="Path to scanner_specs.schema")
@click.option("--verbose", is_flag=True, default=False, help="Print full request/response trace and leaked data")
@click.option("--explain", is_flag=True, default=False, help="Plain-English summary of sent/received/expected and exploited capability")
@click.option("--timeout", type=float, default=12.0, show_default=True, help="Per-request read timeout in seconds")
def scan_range_cmd(host: str, ports: str, scheme: str, spec: Optional[str], verbose: bool, explain: bool, timeout: float) -> None:
    spec_file = spec
    if spec_file is None:
        spec_index = load_spec()
    else:
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
        findings = run_full_http_checks(base, spec_index, trace=trace, verbose=verbose, timeout=timeout, transport="auto")
        passed = sum(1 for f in findings if f.passed)
        failed = sum(1 for f in findings if not f.passed)
        table.add_row(base, f"passed={passed} failed={failed}")
    console.print(table)
    if explain:
        console.rule("Explanation")
        console.print("Re-run single-target scan with --explain for detailed narrative.")


def _explain_single(finding, spec_index: Dict[str, Any], trace: list[dict]) -> list[str]:
    lines: list[str] = []
    spec = spec_index.get(finding.id)
    test_name = f"{finding.id} - {finding.title}"
    lines.append(f"Test: {test_name}")
    # Expected outcome heuristics per ID
    expected = "Per spec: server should enforce safe behavior."
    if finding.id == "A-01":
        expected = "Unauthenticated requests to tools/list should be denied (401/403)."
    elif finding.id == "T-02":
        expected = "Server should use HTTPS with proper transport security."
    elif finding.id == "X-01":
        expected = "Dangerous tools must be constrained and gated by validation."
    elif finding.id == "P-02":
        expected = "Tool descriptions should not contain manipulative/injection-style instructions."
    elif finding.id == "X-03":
        expected = "Tool descriptions/names should be stable between listings."
    elif finding.id == "R-01":
        expected = "Path traversal URIs must be rejected."
    elif finding.id == "R-03":
        expected = "Sensitive resources (credentials/secrets) must not be listed or readable."
    elif finding.id == "R-04":
        expected = "User-controlled uriTemplate inputs must be validated to prevent leakage."
    elif finding.id == "R-05":
        expected = "Private namespaces (private://) should not be readable."
    elif finding.id == "P-03":
        expected = "External resources must not trigger prompt injection when summarized."
    elif finding.id == "A-03":
        expected = "Server must not expose or pass through upstream access tokens."
    elif finding.id == "RC-01":
        expected = "Remote access controls must not be exposed/enabled without proper gates."
    lines.append(f"Expected: {expected}")
    # What scanner got
    got = finding.details
    lines.append(f"Got: {got}")
    # Why fail/pass
    if finding.passed:
        lines.append("Result: PASS — behavior matches expected security posture.")
    else:
        lines.append("Result: FAIL — observed behavior violates the expected protection.")
    # Remediation from spec
    if getattr(spec, "remediation", None):
        lines.append(f"Remediation: {spec.remediation}")
    return lines


@main.command("rpc")
@click.option("--url", required=True, help="Target MCP server base URL (http:// or https://)")
@click.option("--method", required=True, help="JSON-RPC method, e.g., tools/list")
@click.option("--params", default="{}", help='JSON object for params, e.g., "{\"name\":\"tool\",\"arguments\":{}}"')
@click.option("--header", multiple=True, help="Extra request headers, can repeat. Format: 'Key: Value'")
@click.option("--transport", type=click.Choice(["auto", "http", "sse"]), default="auto")
@click.option("--timeout", type=float, default=12.0)
@click.option("--sse-endpoint", help="Explicit SSE path, e.g., /sse")
@click.option("--session-id", help="Pre-supplied session id to include in Mcp-Session-Id header")
@click.option("--verbose", is_flag=True, default=False)
@click.option("--auth-type", type=click.Choice(["bearer", "oauth2-client-credentials"]))
@click.option("--auth-token")
@click.option("--token-url")
@click.option("--client-id")
@click.option("--client-secret")
@click.option("--scope")
def rpc_cmd(url: str, method: str, params: str, header: list[str], transport: str, timeout: float, sse_endpoint: Optional[str], session_id: Optional[str], verbose: bool, auth_type: Optional[str], auth_token: Optional[str], token_url: Optional[str], client_id: Optional[str], client_secret: Optional[str], scope: Optional[str]) -> None:
    try:
        params_obj = json.loads(params) if params else {}
        if not isinstance(params_obj, dict):
            raise ValueError("--params must be a JSON object")
    except Exception as e:
        raise click.ClickException(f"Invalid --params JSON: {e}")
    if transport == "sse":
        console.print("SSE is deprecated in MCP!!! SSE support in the scanner is experimental and may not work!!!")
    headers: Dict[str, Any] = build_auth_headers(auth_type, auth_token, token_url, client_id, client_secret, scope)
    if session_id:
        headers = {**headers, "Mcp-Session-Id": session_id}
    # Parse extra headers
    for h in header or []:
        if ":" not in h:
            raise click.ClickException("--header must be in 'Key: Value' format")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    trace: Any = []
    result = rpc_call(url, method, params_obj, headers=headers, trace=trace, verbose=verbose, timeout=timeout, transport=transport, sse_endpoint=sse_endpoint)
    console.print_json(json.dumps(result))


