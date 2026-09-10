import json

import httpx
import pytest

from src.mcp_scanner.streamable_http import StreamableHttpSession, SessionError
from src.mcp_scanner import http_checks
from src.mcp_scanner.spec import load_spec


def init_result(**changes):
    return {"protocolVersion": "2025-06-18", "capabilities": {},
            "serverInfo": {"name": "test", "version": "1"}, **changes}


def response(payload, result):
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})


@pytest.mark.parametrize('field,value', [('inputSchema', 'bad'), ('description', 7),
    ('inputSchema', {'properties': {'arg': 'bad'}}),
    ('inputSchema', {'required': [7]}), ('inputSchema', {'properties': []})])
@pytest.mark.parametrize('entry', ['scan', 'health'])
def test_review_20_malformed_tools_are_errors(monkeypatch, field, value, entry):
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize':
            return response(p, init_result())
        if p['method'] == 'notifications/initialized':
            return httpx.Response(202)
        key = p['method'].split('/')[0]
        return response(p, {key: [{'name': 'example', field: value}] if key == 'tools' else []})
    real = httpx.Client
    monkeypatch.setattr(http_checks.httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(handle)))
    if entry == 'scan':
        spec = load_spec()
        findings = http_checks.run_full_http_checks('https://test/mcp', {k: spec[k] for k in ('X-02', 'P-02')})
        assert all(f.status == 'error' for f in findings)
    else:
        health = http_checks.get_server_health('https://test/mcp')
        assert health['enumeration_status']['tools'] == 'error'
        assert health['tools'] is None


def test_lifecycle_negotiation_and_unique_ids():
    requests = []
    def handle(request):
        p = json.loads(request.content); requests.append((request, p))
        if p['method'] == 'initialize':
            r = response(p, init_result(protocolVersion='2025-03-26'))
            r.headers['Mcp-Session-Id'] = 'session'
            return r
        if p['method'] == 'notifications/initialized':
            return httpx.Response(202)
        return response(p, {})
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = StreamableHttpSession(client, 'https://test/mcp?sessionId=ordinary-query')
        session.initialize(); session.call('tools/list', {}); session.call('tools/list', {})
    assert [p['method'] for _, p in requests] == ['initialize', 'notifications/initialized', 'tools/list', 'tools/list']
    assert requests[0][1]['params']['capabilities'] == {}
    assert 'id' not in requests[1][1]
    assert requests[2][1]['id'] != requests[3][1]['id']
    for request, _ in requests[1:]:
        assert request.headers['MCP-Protocol-Version'] == '2025-03-26'
        assert request.headers['Mcp-Session-Id'] == 'session'
        assert request.headers.get_list('Accept') == ['application/json, text/event-stream']


@pytest.mark.parametrize('changes', [{'protocolVersion': 'unknown'}, {'serverInfo': None}, {'capabilities': []}])
def test_invalid_initialize_never_sends_initialized(changes):
    requests = []
    def handle(request):
        p = json.loads(request.content); requests.append(p)
        return response(p, init_result(**changes))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = StreamableHttpSession(client, 'https://test/mcp')
        with pytest.raises(SessionError): session.initialize()
        with pytest.raises(SessionError): session.call('tools/list', {})
    assert len(requests) == 1


class OpenStream(httpx.SyncByteStream):
    closed = False
    def __iter__(self):
        yield b': heartbeat\r\n\r\ndata: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'
        yield b'data: {"jsonrpc":"2.0","id":999,"result":{}}\n\n'
        yield b'data: {"jsonrpc":"2.0",\r\ndata: "id":8,"result":{"ok":true}}\r\n\r\n'
        raise AssertionError('Must stop at matching result without waiting for EOF')
    def close(self): self.closed = True


def test_sse_correlation_multiline_and_early_close():
    stream = OpenStream()
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, headers={'Content-Type': 'text/event-stream'}, stream=stream))) as client:
        session = StreamableHttpSession(client, 'https://test/mcp')
        status, result = session.exchange({'jsonrpc': '2.0', 'id': 8, 'method': 'tools/list'})
    assert result['result']['ok'] and status == 200
    assert stream.closed


@pytest.mark.parametrize('failure', ['timeout', '404'])
def test_tool_calls_are_not_replayed(failure):
    calls = []
    def handle(request):
        calls.append(request)
        if failure == 'timeout': raise httpx.ReadTimeout('lost response')
        return httpx.Response(404)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = StreamableHttpSession(client, 'https://test/mcp'); session.ready = True
        if failure == 'timeout':
            with pytest.raises(httpx.ReadTimeout): session.call('tools/call', {})
        else:
            assert session.call('tools/call', {})[0] == 404
    assert len(calls) == 1


def test_failed_initialized_notification_gates_calls():
    requests = []
    def handle(request):
        p = json.loads(request.content); requests.append(p)
        return response(p, init_result()) if p['method'] == 'initialize' else httpx.Response(500)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = StreamableHttpSession(client, 'https://test/mcp')
        with pytest.raises(SessionError, match='Notification'): session.initialize()
        with pytest.raises(SessionError, match='not initialized'): session.call('tools/list', {})
    assert len(requests) == 2


@pytest.mark.parametrize('kind', ['deadline', 'size'])
def test_response_limits_close_stream(monkeypatch, kind):
    from src.mcp_scanner import streamable_http
    ticks = [0]
    class Stream(httpx.SyncByteStream):
        closed = False
        def __iter__(self):
            for _ in range(10):
                ticks[0] += 1
                yield b': heartbeat\n\n'
        def close(self): self.closed = True
    stream = Stream()
    monkeypatch.setattr(streamable_http.time, 'monotonic', lambda: ticks[0])
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, headers={'Content-Type': 'text/event-stream'}, stream=stream))) as client:
        session = StreamableHttpSession(client, 'https://test/mcp', timeout=3)
        if kind == 'size': session.MAX_BYTES = 1
        with pytest.raises(SessionError, match='deadline|size'):
            session.exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
    assert stream.closed


@pytest.mark.parametrize('method', ['ping', 'sampling/createMessage'])
def test_server_requests_do_not_replace_client_result(method):
    replies = []
    def handle(request):
        p = json.loads(request.content)
        if 'method' not in p:
            replies.append(p)
            return httpx.Response(202)
        messages = [{'jsonrpc': '2.0', 'id': 'server-request', 'method': method},
                    {'jsonrpc': '2.0', 'id': 1, 'result': {}}]
        return httpx.Response(200, headers={'Content-Type': 'text/event-stream'},
                              content=''.join('data: '+json.dumps(m)+'\n\n' for m in messages))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = StreamableHttpSession(client, 'https://test/mcp')
        assert session.exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})[1]['id'] == 1
    assert len(replies) == 1 and replies[0]['id'] == 'server-request'
    assert ('result' if method == 'ping' else 'error') in replies[0]
