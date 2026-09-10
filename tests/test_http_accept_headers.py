"""Regression coverage for issue #14 using real HTTPX request construction."""

import json

import httpx
import pytest

from src.mcp_scanner import http_checks
from src.mcp_scanner.spec import load_spec


@pytest.mark.parametrize("entry_point", ["scan", "rpc", "health"])
@pytest.mark.parametrize("transport", ["auto", "http"])
@pytest.mark.parametrize("response_type", ["json", "sse"])
@pytest.mark.parametrize("accept_headers", [
    {},
    {"Accept": "*/*"},
    {"accept": "application/json"},
    {"aCcEpT": "application/json, text/event-stream"},
])
def test_mcp_posts_accept_json_and_sse(
    monkeypatch, entry_point, transport, response_type, accept_headers
):
    requests = []
    tools = [{"name": "example", "description": "Example tool", "inputSchema": {}}]

    def handle(request):
        requests.append(request)
        accepted = {value.strip() for value in request.headers["Accept"].split(",")}
        if not {"application/json", "text/event-stream"} <= accepted:
            return httpx.Response(406, json={"error": "Client must accept JSON and SSE"})
        payload = json.loads(request.content)
        method = payload["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "test", "version": "1"}, "capabilities": {"tools": {}}}
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "prompts/list":
            result = {"prompts": []}
        elif method == "resources/list":
            result = {"resources": []}
        else:
            return httpx.Response(400, json={"error": "Unexpected method"})
        data = {"jsonrpc": "2.0", "id": payload["id"], "result": result}
        headers = {"Mcp-Session-Id": "test-session"} if method == "initialize" else {}
        if response_type == "sse":
            return httpx.Response(
                200, headers={**headers, "Content-Type": "text/event-stream"},
                content=f"event: message\ndata: {json.dumps(data)}\n\n",
            )
        return httpx.Response(200, headers=headers, json=data)

    real_client = httpx.Client

    def mock_client(**kwargs):
        return real_client(**kwargs, transport=httpx.MockTransport(handle))

    monkeypatch.setattr(http_checks.httpx, "Client", mock_client)
    headers = {**accept_headers, "Authorization": "Bearer test-token", "X-Test": "keep"}
    original_headers = headers.copy()
    url = "https://example.test/mcp"
    if entry_point == "scan":
        spec = load_spec()
        result = http_checks.run_full_http_checks(
            url, {"BASE-01": spec["BASE-01"]}, headers=headers, transport=transport,
        )
        assert len(result) == 1
        assert result[0].id == "BASE-01" and result[0].passed
    elif entry_point == "rpc":
        result = http_checks.rpc_call(url, "tools/list", {}, headers=headers, transport=transport)
        assert result["result"]["tools"] == tools
    else:
        result = http_checks.get_server_health(url, headers=headers, transport=transport)
        assert "capabilities" in result["initialize"]["result"]
        assert result["tools"] == tools

    # Assert outside the handler: scanner exception handling must not swallow a
    # failed assertion and accidentally turn this regression test into a pass.
    assert len(requests) >= 2
    assert json.loads(requests[0].content)["method"] == "initialize"
    for index, request in enumerate(requests):
        assert request.method == "POST"
        assert request.headers.get_list("Accept") == ["application/json, text/event-stream"]
        assert request.headers["Content-Type"] == "application/json"
        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.headers["X-Test"] == "keep"
        assert request.headers["MCP-Protocol-Version"] == "2025-06-18"
        if index:
            assert request.headers["Mcp-Session-Id"] == "test-session"
    assert headers == original_headers


@pytest.mark.parametrize("entry_point", ["scan", "rpc", "health"])
def test_explicit_sse_get_keeps_event_stream_accept(monkeypatch, entry_point):
    requests = []

    def handle(request):
        requests.append(request)
        # Stop after the handshake request; this test covers header selection,
        # not the legacy transport's connection lifecycle.
        return httpx.Response(404)

    real_client = httpx.Client
    monkeypatch.setattr(
        http_checks.httpx, "Client",
        lambda **kwargs: real_client(**kwargs, transport=httpx.MockTransport(handle)),
    )
    options = {"transport": "sse", "headers": {"Authorization": "Bearer test-token"}}
    if entry_point == "scan":
        http_checks.run_full_http_checks("https://example.test/sse", {}, **options)
    elif entry_point == "rpc":
        http_checks.rpc_call("https://example.test/sse", "tools/list", {}, **options)
    else:
        http_checks.get_server_health("https://example.test/sse", **options)
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].headers["Accept"] == "text/event-stream"
    assert requests[0].headers["Authorization"] == "Bearer test-token"
