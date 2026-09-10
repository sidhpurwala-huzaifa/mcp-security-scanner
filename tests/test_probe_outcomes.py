import json

import httpx
import pytest
from click.testing import CliRunner

from src.mcp_scanner import cli, http_checks
from src.mcp_scanner.spec import load_spec
from src.mcp_scanner.models import Report
from tests.test_issue18_acceptance import init, ok, install


CHECKS = ['R-01', 'R-02', 'A-03', 'RC-01', 'X-02', 'P-01', 'P-03', 'R-03', 'R-04', 'R-05']


def handler_for(active):
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize': return init(p)
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        if p['method'] == 'tools/list':
            return ok(p, {'tools': [{'name': 'remote_access_summarize', 'description': 'summarize remote access',
                                   'inputSchema': {'properties': {'arg': {'type': 'string'}}}}]})
        if p['method'] == 'prompts/list':
            return ok(p, {'prompts': [{'name': 'prompt', 'inputSchema': {'required': ['arg'], 'properties': {'arg': {'type': 'string'}}}}]})
        if p['method'] == 'resources/list':
            return ok(p, {'resources': [{'uri': 'private://secret', 'name': 'secret', 'uriTemplate': 'notes://{user}'},
                                       {'uri': 'external://page', 'name': 'page'}]})
        return active(p)
    return handle


@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('failure', ['503', 'rpc', 'timeout', 'malformed', 'tool_error'])
def test_active_checks_never_treat_failures_as_evidence(monkeypatch, check, failure):
    def active(p):
        if failure == 'timeout': raise httpx.ReadTimeout('backend unavailable')
        if failure == '503': return httpx.Response(503, text='uid=0 password root:x:')
        if failure == 'malformed': return httpx.Response(200, text='invalid JSON')
        if failure == 'tool_error': return ok(p, {'isError': True, 'content': [{'type': 'text', 'text': 'uid=0 password root:x:'}]})
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': p['id'], 'error': {'code': -32603, 'message': 'uid=0 password root:x:'}})
    install(monkeypatch, handler_for(active))
    spec = load_spec()
    result = http_checks.run_full_http_checks('https://test/mcp', {check: spec[check]}, transport='http')
    assert len(result) == 1 and result[0].status == 'error'
    assert Report.new('test', result).exit_code == 2


@pytest.mark.parametrize('check', ['R-01', 'R-02', 'RC-01', 'R-03', 'R-04', 'R-05'])
@pytest.mark.parametrize('status', [401, 403])
def test_expected_access_denials_still_pass(monkeypatch, check, status):
    install(monkeypatch, handler_for(lambda p: httpx.Response(status, text='denied')))
    spec = load_spec()
    result = http_checks.run_full_http_checks('https://test/mcp', {check: spec[check]}, transport='http')
    assert len(result) == 1 and result[0].status == 'pass'


def test_prompt_invalid_params_rejection_still_passes(monkeypatch):
    def active(p):
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': p['id'], 'error': {'code': -32602, 'message': 'Invalid arguments'}})
    install(monkeypatch, handler_for(active))
    spec = load_spec()
    result = http_checks.run_full_http_checks('https://test/mcp', {'P-01': spec['P-01']}, transport='http')
    assert result[0].status == 'pass'


def test_timeout_does_not_suppress_independent_confirmed_failure(monkeypatch):
    def active(p):
        if '..' in p['params']['uri']: raise httpx.ReadTimeout('backend unavailable')
        return ok(p, {'contents': [{'text': 'root:x:0:0'}]})
    install(monkeypatch, handler_for(active))
    spec = load_spec()
    result = http_checks.run_full_http_checks('https://test/mcp', {k: spec[k] for k in ['BASE-01', 'R-01', 'R-02']}, transport='http')
    assert {f.id: f.status for f in result} == {'BASE-01': 'pass', 'R-01': 'error', 'R-02': 'fail'}


def test_cli_preserves_json_report_and_exit_two(monkeypatch):
    install(monkeypatch, handler_for(lambda p: httpx.Response(503)))
    spec = load_spec()
    monkeypatch.setattr(cli, 'load_spec', lambda *args: {'R-01': spec['R-01']})
    result = CliRunner().invoke(cli.main, ['scan', '--url', 'https://test/mcp', '--transport', 'http', '--format', 'json'])
    assert result.exit_code == 2
    assert json.loads(result.stdout)['summary']['errors'] == 1


@pytest.mark.parametrize('verbose', [False, True])
def test_learned_secret_redacted_in_scan_details_and_rpc(monkeypatch, verbose):
    token = 'session-"quoted"-secret'
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize': return init(p, {'Mcp-Session-Id': token})
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        if p['method'].endswith('/list'): return ok(p, {p['method'].split('/')[0]: []})
        return ok(p, {'contents': [{'text': token}]})
    install(monkeypatch, handle)
    spec = load_spec(); trace = []
    findings = http_checks.run_full_http_checks('https://test/mcp', {'R-01': spec['R-01']}, transport='http', trace=trace, verbose=verbose)
    assert findings[0].status == 'fail'
    assert token not in findings[0].details and '[redacted]' in findings[0].details
    assert 'quoted' not in json.dumps(trace)
    result = http_checks.rpc_call('https://test/mcp', 'resources/read', {}, transport='http')
    assert '[redacted]' in json.dumps(result) and 'quoted' not in json.dumps(result)


def test_error_body_limit_closes_without_reading_endlessly():
    from src.mcp_scanner.streamable_http import StreamableHttpSession
    class Stream(httpx.SyncByteStream):
        closed = False
        def __iter__(self):
            yield b'x' * (20 * 1024)
            raise AssertionError('Error body must stop at size limit')
        def close(self): self.closed = True
    stream = Stream()
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503, stream=stream))) as client:
        session = StreamableHttpSession(client, 'https://test/mcp')
        status, data = session.exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
    assert status == 503 and data['diagnostic_truncated'] is True
    assert len(data['error']['message']) == 16 * 1024 and stream.closed


def test_legacy_http_error_details_are_preserved(monkeypatch):
    from tests.test_legacy_http_session import LegacyServer
    server = LegacyServer()
    def handle(request):
        if request.method == 'POST':
            return httpx.Response(503, json={'error': {'code': -32000, 'message': 'legacy backend unavailable'}})
        return server.handle(request)
    install(monkeypatch, handle)
    result = http_checks.get_server_health('https://example.test/sse', transport='sse')
    assert result['initialize_http_status'] == 503
    assert 'legacy backend unavailable' in result['errors']['initialize']
    assert server.closed


def test_redaction_secrets_are_isolated_between_calls(monkeypatch):
    token = 'learned-session-value'
    counter = [0]
    def handle(request):
        p = json.loads(request.content)
        if p['method'] == 'initialize':
            counter[0] += 1
            return init(p, {'Mcp-Session-Id': token} if counter[0] == 1 else {})
        if p['method'] == 'notifications/initialized': return httpx.Response(202)
        return ok(p, {'value': token})
    install(monkeypatch, handle)
    first = http_checks.rpc_call('https://test/mcp', 'ping', {}, transport='http')
    second = http_checks.rpc_call('https://test/mcp', 'ping', {}, transport='http')
    assert first['result']['value'] == '[redacted]'
    assert second['result']['value'] == token
