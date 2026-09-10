"""Issue #18: failed prerequisites must never turn into security passes."""

import json

import httpx
import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from src.mcp_scanner import cli, http_checks
from src.mcp_scanner.models import Finding, Outcome, Report
from src.mcp_scanner.spec import load_spec


def selected(*keys):
    spec = load_spec()
    return {key: spec[key] for key in keys}


def reply(payload, result=None, status=200):
    if result is None:
        method = payload["method"]
        result = {"capabilities": {}} if method == "initialize" else {method.split("/")[0]: []}
    return httpx.Response(status, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})


@pytest.fixture
def endpoint(monkeypatch):
    real_client = httpx.Client
    requests = []

    def install(handler):
        def handle(request):
            requests.append(request)
            # The CLI reachability preflight is not an MCP enumeration.
            if request.method == "GET":
                return httpx.Response(200, json={"token_endpoint": "token", "authorization_endpoint": "auth"})
            return handler(json.loads(request.content))

        monkeypatch.setattr(http_checks.httpx, "Client", lambda **kw: real_client(
            **kw, transport=httpx.MockTransport(handle),
        ))
        return requests

    return install


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"error": {"code": -32000, "message": "Denied"}}),
    httpx.Response(406, text="Not acceptable"),
    httpx.Response(500, json={"jsonrpc": "2.0", "id": 0, "result": {"capabilities": {}}}),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 0, "error": {"code": -32600}}),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 0, "result": None}),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 0, "result": {"capabilities": None}}),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 7, "result": {"capabilities": {}}}),
    httpx.Response(200, text="not JSON"),
])
def test_failed_initialize_gates_checks_and_preserves_independent_results(endpoint, response):
    requests = endpoint(lambda payload: response)
    spec = selected("BASE-01", "X-01", "P-02", "R-03", "A-01", "T-02", "A-02")
    original = spec.copy()
    findings = http_checks.run_full_http_checks("https://example.test/mcp", spec, transport="http")
    by_id = {f.id: f for f in findings}
    assert by_id["BASE-01"].status == Outcome.error
    assert f"HTTP {response.status_code}" in by_id["BASE-01"].details
    for key in ("X-01", "P-02", "R-03", "A-01"):
        assert by_id[key].status == Outcome.skipped
        assert by_id[key].passed is None
    assert by_id["T-02"].passed is True
    assert by_id["A-02"].passed is True
    assert [json.loads(r.content)["method"] for r in requests if r.method == "POST"] == ["initialize"]
    assert spec == original
    report = Report.new("test", findings)
    assert report.summary["failed"] == 0
    assert report.summary["errors"] == 1
    assert report.summary["skipped"] == 4
    assert report.exit_code == 2


def test_initialize_exception_and_missing_baseline_cannot_hide_error(endpoint):
    def handle(payload):
        raise httpx.ConnectError("offline")
    endpoint(handle)
    findings = http_checks.run_full_http_checks("https://example.test/mcp", selected("X-01"))
    assert [(f.id, f.status) for f in findings] == [("BASE-01", Outcome.error), ("X-01", Outcome.skipped)]
    assert "ConnectError" in findings[0].details


@pytest.mark.parametrize("key,affected", [
    ("tools", ("X-01", "X-02", "X-03", "P-02", "P-03", "RC-01")),
    ("prompts", ("P-01",)),
    ("resources", ("R-03", "R-04", "R-05", "P-03")),
])
@pytest.mark.parametrize("failure", ["http", "rpc", "null", "missing", "bad-item", "wrong-id", "exception", "partial"])
def test_enumeration_failure_is_not_an_empty_list(endpoint, key, affected, failure):
    def handle(payload):
        if payload["method"] != key + "/list":
            return reply(payload)
        if failure == "exception":
            raise httpx.ConnectError("enumeration disconnected")
        if failure == "http":
            return reply(payload, {key: []}, status=503)
        if failure == "rpc":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 99, "error": {"code": -32601}})
        if failure == "wrong-id":
            return reply({**payload, "id": 12})
        result = {"null": {key: None}, "missing": {}, "bad-item": {key: [None]}, "partial": {key: [], "nextCursor": "more"}}
        return reply(payload, result[failure])

    requests = endpoint(handle)
    spec = selected("BASE-01", *affected)
    findings = http_checks.run_full_http_checks("https://example.test/mcp", spec)
    assert len(findings) == len(spec)
    by_id = {f.id: f for f in findings}
    assert by_id["BASE-01"].passed is True
    for check_id in affected:
        assert by_id[check_id].status == Outcome.error
        assert by_id[check_id].passed is None
        assert key + "/list" in by_id[check_id].details
    assert not any(json.loads(r.content)["method"] in ("tools/call", "resources/read", "prompts/get") for r in requests)


def test_failed_second_listing_is_not_a_rug_pull(endpoint):
    calls = 0
    def handle(payload):
        nonlocal calls
        if payload["method"] == "tools/list":
            calls += 1
            if calls == 2:
                return httpx.Response(500)
            return reply(payload, {"tools": [{"name": "example", "description": "stable", "inputSchema": {}}]})
        return reply(payload)
    endpoint(handle)
    findings = http_checks.run_full_http_checks("https://example.test/mcp", selected("X-03"))
    assert len(findings) == 1
    assert findings[0].status == Outcome.error


def test_failed_tools_do_not_suppress_independent_resource_checks(endpoint):
    def handle(payload):
        if payload["method"] == "tools/list":
            return httpx.Response(503)
        if payload["method"] == "resources/list":
            return reply(payload, {"resources": [{"uri": "file:///public", "name": "public"}]})
        return reply(payload)
    endpoint(handle)
    findings = http_checks.run_full_http_checks("https://example.test/mcp", selected("X-01", "R-03"))
    assert {f.id: f.status for f in findings} == {"X-01": Outcome.error, "R-03": Outcome.passed}


def test_successful_empty_enumerations_are_explicitly_skipped(endpoint):
    endpoint(reply)
    findings = http_checks.run_full_http_checks(
        "https://example.test/mcp", selected("BASE-01", "X-01", "P-01", "R-03"),
    )
    assert [f.status for f in findings] == [Outcome.passed, Outcome.skipped, Outcome.skipped, Outcome.skipped]
    report = Report.new("test", findings)
    assert report.summary["errors"] == report.summary["failed"] == 0
    assert report.exit_code == 0


def test_authentication_probe_denial_still_passes(endpoint):
    def handle(payload):
        if payload["id"] == 3:
            return httpx.Response(401, json={"error": "authentication required"})
        return reply(payload)
    endpoint(handle)
    findings = http_checks.run_full_http_checks("https://example.test/mcp", selected("BASE-01", "A-01"))
    assert all(f.passed is True for f in findings)


def test_health_preserves_http_status_and_does_not_enumerate_after_failure(endpoint):
    requests = endpoint(lambda payload: httpx.Response(406, json={"error": "Denied"}))
    trace = []
    result = http_checks.get_server_health("https://example.test/mcp", trace=trace, verbose=True, transport="http")
    assert result["status"] == "error"
    assert result["initialize_http_status"] == 406
    assert result["tools"] is result["prompts"] is result["resources"] is None
    assert set(result["enumeration_status"].values()) == {"skipped"}
    assert len(requests) == 1
    assert [entry["status"] for entry in trace if entry["direction"] == "recv"] == [406]


def test_partial_health_distinguishes_unavailable_from_empty(endpoint):
    def handle(payload):
        return httpx.Response(503) if payload["method"] == "tools/list" else reply(payload)
    endpoint(handle)
    result = http_checks.get_server_health("https://example.test/mcp", transport="http")
    assert result["status"] == "error"
    assert result["tools"] is None
    assert result["prompts"] == result["resources"] == []
    assert result["enumeration_status"] == {"tools": "error", "prompts": "ok", "resources": "ok"}
    assert "HTTP 503" in result["errors"]["tools/list"]


def test_diagnostics_redact_supplied_credentials(endpoint):
    endpoint(lambda payload: httpx.Response(401, json={"error": {"message": "token: private-token"}}))
    trace = []
    result = http_checks.get_server_health("https://example.test/mcp", headers={"Authorization": "Bearer private-token"}, trace=trace, verbose=True)
    assert "private-token" not in json.dumps(result)
    assert "[redacted]" in result["errors"]["initialize"]
    assert "private-token" not in json.dumps(trace)


def finding(**kwargs):
    return Finding(id="X-01", title="Check", category="test", severity="high", **kwargs)


def test_legacy_findings_round_trip_and_errors_do_not_count_as_vulnerabilities():
    old = finding(passed=False)
    assert old.status == Outcome.failed
    error = finding(status="error")
    skipped = finding(status="skipped")
    report = Report.new("test", [old, error, skipped, finding(passed=True)])
    data = json.loads(report.model_dump_json())
    assert data["schema_version"] == 2
    assert data["summary"]["high"] == 1
    assert data["summary"]["errors"] == data["summary"]["skipped"] == 1
    assert data["findings"][1]["passed"] is None
    assert Report.model_validate(data).summary == report.summary
    assert report.exit_code == 2


@pytest.mark.parametrize("kwargs", [{"status": "error", "passed": True}, {"status": "skipped", "passed": False}, {"status": "pass", "passed": False}])
def test_contradictory_outcomes_are_rejected(kwargs):
    with pytest.raises(ValidationError):
        finding(**kwargs)


@pytest.mark.parametrize("health", [False, True])
def test_cli_json_error_is_machine_readable_and_nonzero(endpoint, monkeypatch, health):
    endpoint(lambda payload: httpx.Response(406))
    monkeypatch.setattr(cli, "load_spec", lambda: selected("BASE-01", "X-01"))
    args = ["scan", "--url", "https://example.test/mcp", "--format", "json"]
    if health:
        args.append("--only-health")
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 2, result.output
    data = json.loads(result.stdout)
    assert "All checks passed" not in result.output
    if health:
        assert data["tools"] is None
    else:
        assert data["summary"]["errors"] == 1


def test_range_uses_outcomes_and_nonzero_exit(monkeypatch):
    monkeypatch.setattr(cli, "run_full_http_checks", lambda *a, **kw: [finding(status="error")])
    result = CliRunner().invoke(cli.main, ["scan-range", "--host", "example.test", "--ports", "9000"])
    assert result.exit_code == 2
    assert "errors=1" in result.output and "failed=0" in result.output


@pytest.mark.parametrize("status,exit_code", [("pass", 0), ("fail", 1), ("error", 2), ("skipped", 0)])
def test_cli_exit_codes_and_summary_messages(endpoint, monkeypatch, status, exit_code):
    endpoint(reply)
    monkeypatch.setattr(cli, "run_full_http_checks", lambda *a, **kw: [finding(status=status)])
    result = CliRunner().invoke(cli.main, ["scan", "--url", "https://example.test/mcp", "--format", "json"])
    assert result.exit_code == exit_code
    assert json.loads(result.stdout)["findings"][0]["status"] == status
    assert ("All checks passed" in result.stderr) == (status == "pass")


def test_legacy_endpoint_event_is_not_a_successful_initialization(monkeypatch):
    requests = []
    real_client = httpx.Client
    def handle(request):
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content="event: endpoint\ndata: /messages?sessionId=test\n\n")
    monkeypatch.setattr(http_checks.httpx, "Client", lambda **kw: real_client(**kw, transport=httpx.MockTransport(handle)))
    findings = http_checks.run_full_http_checks("https://example.test", selected("BASE-01", "X-01"), transport="sse")
    assert [f.status for f in findings] == [Outcome.error, Outcome.skipped]
    assert "not a verified MCP initialization" in findings[0].details
    assert [request.method for request in requests] == ["GET"]


def test_explanation_does_not_describe_an_error_as_a_vulnerability():
    text = " ".join(cli._explain_single(finding(status="error", details="tools/list failed"), {}, []))
    assert "not evaluated" in text
    assert "violates" not in text


@pytest.mark.parametrize("health", [False, True])
def test_legacy_warning_does_not_pollute_json_stdout(endpoint, health):
    endpoint(reply)
    args = ["scan", "--url", "https://example.test/mcp", "--format", "json", "--transport", "sse"]
    if health:
        args.append("--only-health")
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 2
    json.loads(result.stdout)
    assert "experimental" in result.stderr


def test_preflight_connection_failure_has_incomplete_exit_code(monkeypatch):
    real_client = httpx.Client
    def handle(request):
        raise httpx.ConnectError("unreachable")
    monkeypatch.setattr(cli.httpx, "Client", lambda **kw: real_client(**kw, transport=httpx.MockTransport(handle)))
    result = CliRunner().invoke(cli.main, ["scan", "--url", "https://example.test/mcp", "--format", "json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Cannot reach MCP server" in result.stderr
