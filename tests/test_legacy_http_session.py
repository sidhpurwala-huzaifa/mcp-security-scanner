"""Legacy compatibility requires one live GET and real MCP initialization."""
from collections import deque
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from src.mcp_scanner import http_checks
from src.mcp_scanner.http_session import HttpSession
from src.mcp_scanner.spec import load_spec


class LegacyServer:
    def __init__(self, endpoint='/messages?opaque=abc', init_error=False, missing=False):
        self.endpoint, self.init_error, self.missing = endpoint, init_error, missing
        self.events = deque([f'event: endpoint\r\ndata: {endpoint}\r\n\r\n'.encode()])
        self.requests = []
        self.closed = False
        owner = self
        class Stream(httpx.SyncByteStream):
            def __iter__(self):
                while True:
                    if not owner.events:
                        raise httpx.ReadTimeout('No legacy reply')
                    yield owner.events.popleft()
            def close(self): owner.closed = True
        self.stream = Stream()

    def handle(self, request):
        self.requests.append(request)
        if request.method == 'GET':
            return httpx.Response(200, headers={'Content-Type': 'text/event-stream'}, stream=self.stream)
        if request.url.path == '/sse':
            return httpx.Response(405)
        p = json.loads(request.content)
        if 'id' in p:
            if p['method'] == 'initialize':
                result = {'protocolVersion': '2024-11-05', 'capabilities': {},
                          'serverInfo': {'name': 'legacy', 'version': '1'}}
            else:
                result = {p['method'].split('/')[0]: []}
            data = {'jsonrpc': '2.0', 'id': p['id'], 'result': result}
            if self.init_error and p['method'] == 'initialize':
                data = {'jsonrpc': '2.0', 'id': p['id'], 'error': {'code': -32600}}
            self.events.append(b'data: {"jsonrpc":"2.0","method":"notifications/message"}\n\n')
            self.events.append(b'data: {"jsonrpc":"2.0","id":987654,"result":{}}\n\n')
            if not self.missing:
                self.events.append(('data: '+json.dumps(data)+'\n\n').encode())
        return httpx.Response(202)


def invoke(entry, **options):
    url = options.pop('url', 'https://example.test/sse')
    if entry == 'scan':
        spec = load_spec()
        return http_checks.run_full_http_checks(url, {k: spec[k] for k in ('BASE-01', 'X-01', 'T-03')}, **options)
    if entry == 'health':
        return http_checks.get_server_health(url, **options)
    return http_checks.rpc_call(url, 'tools/list', {}, **options)


@pytest.mark.parametrize('entry', ['scan', 'health', 'rpc'])
@pytest.mark.parametrize('mode', ['sse', 'auto'])
@pytest.mark.parametrize('endpoint', ['/messages?opaque=abc', 'messages?sessionId=abc', 'https://example.test/messages'])
def test_legacy_lifecycle_across_entry_points(monkeypatch, entry, mode, endpoint):
    server = LegacyServer(endpoint)
    real = httpx.Client
    monkeypatch.setattr(http_checks.httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(server.handle)))
    result = invoke(entry, transport=mode, headers={'aCcEpT': '*/*', 'Authorization': 'Bearer keep'})
    if entry == 'scan':
        assert {f.id: f.status for f in result} == {'BASE-01': 'pass', 'X-01': 'skipped', 'T-03': 'skipped'}
    elif entry == 'health':
        assert result['status'] == 'ok' and result['tools'] == []
        assert result['transport'] == 'sse' and result['initialize_http_status'] == 202
    else:
        assert result['result']['tools'] == []
    gets = [r for r in server.requests if r.method == 'GET']
    posts = [r for r in server.requests if r.method == 'POST' and r.url.path != '/sse']
    assert len(gets) == 1 and server.closed
    assert gets[0].headers.get_list('Accept') == ['text/event-stream']
    payloads = [json.loads(r.content) for r in posts]
    assert [p['method'] for p in payloads[:2]] == ['initialize', 'notifications/initialized']
    assert payloads[0]['params']['protocolVersion'] == '2024-11-05'
    assert len({p['id'] for p in payloads if 'id' in p}) == len([p for p in payloads if 'id' in p])
    for request in posts:
        assert request.headers.get_list('Accept') == ['application/json, text/event-stream']
        assert request.headers['Authorization'] == 'Bearer keep'
        assert 'Mcp-Session-Id' not in request.headers


@pytest.mark.parametrize('status', [400, 401, 403, 406, 500])
def test_auto_does_not_hide_http_errors(status):
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(status)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = HttpSession(client, 'https://test/sse')
        with pytest.raises(Exception): session.initialize()
        session.close()
    assert [r.method for r in requests] == ['POST']


@pytest.mark.parametrize('endpoint', ['https://other.test/post', '//other.test/post', 'http://example.test/post',
                                     'https://user:pass@example.test/post', '/post#fragment', 'data:text/plain,bad'])
def test_untrusted_endpoint_never_receives_credentials(endpoint):
    server = LegacyServer(endpoint)
    with httpx.Client(transport=httpx.MockTransport(server.handle), headers={'Authorization': 'Bearer secret'}) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        with pytest.raises(Exception, match='original origin'): session.initialize()
        session.close()
    assert len(server.requests) == 1 and server.closed


@pytest.mark.parametrize('failure', ['init_error', 'missing'])
def test_failed_legacy_initialization_gates_scan(monkeypatch, failure):
    server = LegacyServer(**{failure: True})
    real = httpx.Client
    monkeypatch.setattr(http_checks.httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(server.handle)))
    result = invoke('scan', transport='sse')
    assert {f.id: f.status for f in result} == {'BASE-01': 'error', 'X-01': 'skipped', 'T-03': 'skipped'}
    assert [json.loads(r.content)['method'] for r in server.requests if r.method == 'POST'] == ['initialize']
    assert server.closed


def test_explicit_http_never_falls_back():
    server = LegacyServer()
    with httpx.Client(transport=httpx.MockTransport(server.handle)) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='http')
        with pytest.raises(Exception): session.initialize()
        session.close()
    assert [r.method for r in server.requests] == ['POST']


def test_disconnect_does_not_reopen_or_replay_tool():
    server = LegacyServer()
    with httpx.Client(transport=httpx.MockTransport(server.handle)) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        session.initialize(); server.missing = True
        with pytest.raises(httpx.ReadTimeout): session.call('tools/call', {'name': 'side-effect'})
        with pytest.raises(Exception, match='not initialized'): session.call('tools/list', {})
        session.close()
    assert sum(r.method == 'GET' for r in server.requests) == 1
    assert sum(r.method == 'POST' and json.loads(r.content)['method'] == 'tools/call' for r in server.requests) == 1
    assert server.closed


@pytest.mark.parametrize('entry', ['scan', 'health', 'rpc'])
def test_real_persistent_sse_connection(entry):
    events = queue.Queue()
    requests = []
    stop = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_GET(self):
            requests.append(('GET', self.path))
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
            try:
                self.wfile.write(b'event: endpoint\ndata: /messages?opaque=live\n\n'); self.wfile.flush()
                while not stop.is_set():
                    try: data = events.get(timeout=0.05)
                    except queue.Empty: data = b': heartbeat\n\n'
                    self.wfile.write(data); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError): pass
            self.close_connection = True
        def do_POST(self):
            p = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(('POST', p['method']))
            self.send_response(202); self.send_header('Content-Length', '0'); self.end_headers()
            if 'id' in p:
                result = ({'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {'name': 'live', 'version': '1'}}
                          if p['method'] == 'initialize' else {p['method'].split('/')[0]: []})
                events.put(('data: '+json.dumps({'jsonrpc': '2.0', 'id': p['id'], 'result': result})+'\n\n').encode())
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        result = invoke(entry, transport='sse', url=f'http://127.0.0.1:{server.server_port}/sse', timeout=2)
        if entry == 'scan': assert next(f for f in result if f.id == 'BASE-01').status == 'pass'
        elif entry == 'health': assert result['status'] == 'ok'
        else: assert result['result']['tools'] == []
        assert sum(method == 'GET' for method, _ in requests) == 1
    finally:
        stop.set(); server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_failed_initialized_notification_cannot_make_session_ready():
    server = LegacyServer()
    def handle(request):
        if request.method == 'POST' and json.loads(request.content)['method'] == 'notifications/initialized':
            return httpx.Response(500)
        return server.handle(request)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        with pytest.raises(Exception, match='Notification'): session.initialize()
        with pytest.raises(Exception, match='not initialized'): session.call('tools/list', {})
        session.close()
    assert server.closed


def test_auto_404_fallback_and_custom_sse_path():
    server = LegacyServer()
    def handle(request):
        if request.method == 'POST' and request.url.path == '/mcp':
            return httpx.Response(404)
        return server.handle(request)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        session = HttpSession(client, 'https://example.test/mcp', sse_endpoint='/sse')
        session.initialize(); session.close()
    assert server.requests[0].url.path == '/sse' and server.closed


def test_endpoint_rotation_stops_without_posting_to_new_endpoint():
    server = LegacyServer()
    with httpx.Client(transport=httpx.MockTransport(server.handle)) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        session.initialize()
        server.events.append(b'event: endpoint\ndata: /rotated\n\n')
        with pytest.raises(Exception, match='endpoint changed'): session.call('tools/call', {})
        session.close()
    assert all(r.url.path != '/rotated' for r in server.requests) and server.closed


def test_missing_endpoint_event_never_posts_initialize():
    server = LegacyServer(); server.events.clear()
    server.events.append(b': heartbeat\n\n')
    with httpx.Client(transport=httpx.MockTransport(server.handle)) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        with pytest.raises(httpx.ReadTimeout): session.initialize()
        session.close()
    assert [r.method for r in server.requests] == ['GET'] and server.closed


def test_legacy_redirect_is_not_followed():
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(302, headers={'Location': 'https://other.test/sse'})
    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        session = HttpSession(client, 'https://example.test/sse', transport='sse')
        with pytest.raises(Exception, match='HTTP 302'): session.initialize()
        session.close()
    assert len(requests) == 1


@pytest.mark.parametrize('ending', ['\n', '\r', '\r\n'])
@pytest.mark.parametrize('split', [False, True])
def test_shared_sse_parser_line_endings_and_split_unicode(ending, split):
    from src.mcp_scanner.streamable_http import SSEReader
    import time
    body = ('\ufeff: comment'+ending+'event: message'+ending+'data: café'+ending+ending).encode()
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            if split:
                for value in body: yield bytes([value])
            else: yield body
            raise AssertionError('A complete event must not wait for EOF')
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, stream=Stream()))) as client:
        with client.stream('GET', 'https://test/sse') as response:
            reader = SSEReader(response, 1024)
            assert reader.next_event(time.monotonic()+1) == ('message', 'café')


def test_advertised_session_secret_is_redacted_in_health_and_trace(monkeypatch):
    server = LegacyServer('/messages?sessionId=private-session')
    real = httpx.Client
    monkeypatch.setattr(http_checks.httpx, 'Client', lambda **kw: real(**kw, transport=httpx.MockTransport(server.handle)))
    trace = []
    result = invoke('health', transport='sse', trace=trace, verbose=True)
    assert result['status'] == 'ok'
    assert 'private-session' not in json.dumps(result)
    assert 'private-session' not in json.dumps(trace)
