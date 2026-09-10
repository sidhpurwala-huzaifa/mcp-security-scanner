"""Additional acceptance probes against the unmodified merged commit."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from src.mcp_scanner import http_checks
from src.mcp_scanner.spec import load_spec


def ok(payload, result, headers=None):
    return httpx.Response(200, headers=headers, json={'jsonrpc': '2.0', 'id': payload['id'], 'result': result})


def init(payload, headers=None):
    return ok(payload, {'protocolVersion': '2025-06-18', 'capabilities': {},
                        'serverInfo': {'name': 'acceptance', 'version': '1'}}, headers)


def install(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(http_checks.httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(handler)))


@pytest.mark.parametrize('status', [401, 503])
def test_http_error_preserves_server_diagnostic(monkeypatch, status):
    install(monkeypatch, lambda r: httpx.Response(status, json={'error': {'code': -32000, 'message': 'backend unavailable'}}))
    result = http_checks.get_server_health('https://test/mcp', transport='http')
    assert result['initialize_http_status'] == status
    assert 'backend unavailable' in result['errors']['initialize'], result['errors']['initialize']


@pytest.mark.parametrize('check', ['R-01', 'R-02', 'A-03'])
def test_active_probe_http_failure_is_not_security_pass(monkeypatch, check):
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize': return init(p)
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        if p['method'].endswith('/list'): return ok(p, {p['method'].split('/')[0]: []})
        return httpx.Response(503, json={'error': {'message': 'backend unavailable'}})
    install(monkeypatch, handle)
    spec = load_spec()
    findings = http_checks.run_full_http_checks('https://test/mcp', {check: spec[check]}, transport='http')
    assert len(findings) == 1
    assert findings[0].status == 'error', findings[0].model_dump()


def test_active_probe_timeout_returns_report_not_exception(monkeypatch):
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize': return init(p)
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        if p['method'].endswith('/list'): return ok(p, {p['method'].split('/')[0]: []})
        raise httpx.ReadTimeout('acceptance timeout')
    install(monkeypatch, handle)
    spec = load_spec()
    findings = http_checks.run_full_http_checks('https://test/mcp', {'R-01': spec['R-01']}, transport='http')
    assert findings[0].status == 'error'


def test_server_assigned_session_token_redacted_when_echoed(monkeypatch):
    token = 'SYNTHETIC-SESSION-SECRET'
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize': return init(p, {'Mcp-Session-Id': token})
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': p['id'], 'error': {'code': -32000, 'message': 'Invalid session '+token}})
    install(monkeypatch, handle)
    trace = []
    result = http_checks.get_server_health('https://test/mcp', transport='http', verbose=True, trace=trace)
    assert token not in json.dumps({'health': result, 'trace': trace})


@pytest.mark.parametrize('entry', ['scan', 'health', 'rpc'])
def test_live_stream_missing_reply_is_bounded(entry):
    stop = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
            try:
                while not stop.is_set():
                    self.wfile.write(b'data: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'); self.wfile.flush()
                    stop.wait(0.01)
            except (BrokenPipeError, ConnectionResetError): pass
            self.close_connection = True
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler); server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    started = time.monotonic()
    try:
        url = f'http://127.0.0.1:{server.server_port}/mcp'
        options = {'transport': 'http', 'timeout': 0.15}
        if entry == 'scan':
            spec = load_spec()
            result = http_checks.run_full_http_checks(url, {'BASE-01': spec['BASE-01'], 'X-01': spec['X-01']}, **options)
            assert [f.status for f in result] == ['error', 'skipped']
        elif entry == 'health':
            result = http_checks.get_server_health(url, **options)
            assert result['status'] == 'error' and result['tools'] is None
        else:
            assert 'error' in http_checks.rpc_call(url, 'tools/list', {}, **options)
        assert time.monotonic() - started < 1.5
    finally:
        stop.set(); server.shutdown(); server.server_close(); thread.join(timeout=2)
