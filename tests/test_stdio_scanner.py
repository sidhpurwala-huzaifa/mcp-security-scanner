"""
Unit tests for stdio_scanner module.

Tests all the error handling behaviors and custom error codes we've implemented.
"""

import pytest
import json
import subprocess
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from src.mcp_scanner.stdio_scanner import (
    StdioClient,
    _is_process_error,
    run_checks_stdio,
    get_stdio_health,
    scan_stdio
)
from src.mcp_scanner.models import Report
from src.mcp_scanner.spec import load_spec


class TestIsProcessError:
    """Test the _is_process_error helper function."""

    @pytest.mark.parametrize("response", [
        {"error": "process_died", "exit_code": 1, "stderr": "error"},
        {"error": "stdio_unavailable", "message": "pipes not available"},
        {"error": "write_failed", "message": "Broken pipe"},
        {"error": "read_failed", "message": "Connection lost"},
        {"error": "no_response", "message": "Process crashed"},
        {"error": "non-json", "raw": "not json"},
    ])
    def test_process_error_detection(self, response):
        """Test that all process error types are correctly detected."""
        assert _is_process_error(response) is True

    @pytest.mark.parametrize("response", [
        {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}},
        {"error": "unknown_error", "message": "something else"},
        {"jsonrpc": "2.0", "id": 1, "result": {}},
    ])
    def test_non_process_error_detection(self, response):
        """Test that non-process errors are correctly identified."""
        assert _is_process_error(response) is False

    @pytest.mark.parametrize("response", [
        "string response",
        123,
        None,
        [],
        True,
    ])
    def test_non_dict_responses(self, response):
        """Test that non-dict responses ARE considered process errors."""
        assert _is_process_error(response) is True


class TestStdioClient:
    """Test the StdioClient class."""

    @patch('subprocess.Popen')
    def test_init_success(self, mock_popen):
        """Test successful client initialization."""
        mock_process = Mock()
        mock_process.poll.return_value = None  # Process is running
        mock_popen.return_value = mock_process

        with patch('time.sleep'):  # Skip the sleep
            client = StdioClient("echo test")

        mock_popen.assert_called_once()
        assert client.proc == mock_process

    @patch('subprocess.Popen')
    def test_init_command_not_found(self, mock_popen):
        """Test initialization with non-existent command."""
        mock_popen.side_effect = FileNotFoundError("No such file")

        with pytest.raises(RuntimeError, match="Command not found"):
            StdioClient("nonexistent-command")

    @patch('subprocess.Popen')
    def test_init_process_exits_immediately(self, mock_popen):
        """Test initialization when process exits immediately."""
        # Configure mock process to simulate immediate exit
        mock_popen.return_value.poll.return_value = 1  # Process exited
        mock_popen.return_value.returncode = 1
        mock_popen.return_value.stderr.read.return_value = "error output"

        with patch('time.sleep'):
            with pytest.raises(RuntimeError, match="exited immediately with code 1"):
                StdioClient("python -c 'import sys; sys.exit(1)'")

    def test_send_recv_process_died(self):
        """Test send_recv when process has died."""
        client = StdioClient.__new__(StdioClient)  # Create without calling __init__
        client.proc = Mock()
        client.proc.poll.return_value = 1  # Process exited
        client.proc.returncode = 1
        client.proc.stderr.read.return_value = "stderr output"

        resp = client.send_recv("test", {})

        expected = {"error": "process_died", "exit_code": 1, "stderr": "stderr output"}
        assert resp == expected

    def test_send_recv_stdio_unavailable(self):
        """Test send_recv when stdio pipes are unavailable."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None  # Process running
        client.proc.stdin = None  # No stdin pipe

        resp = client.send_recv("test", {})

        expected = {"error": "stdio_unavailable", "message": "stdin/stdout pipes not available"}
        assert resp == expected

    def test_send_recv_write_failed(self):
        """Test send_recv when writing to process fails."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None
        client.proc.stdin.write.side_effect = BrokenPipeError("Broken pipe")

        resp = client.send_recv("test", {})

        assert resp["error"] == "write_failed"
        assert "Broken pipe" in resp["message"]

    def test_send_recv_no_response(self):
        """Test send_recv when process returns no data."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None
        client.proc.stdin.write.return_value = None
        client.proc.stdin.flush.return_value = None
        client.proc.stdout.readline.return_value = ""  # EOF

        resp = client.send_recv("test", {})

        expected = {"error": "no_response", "message": "Process returned no data (likely crashed)"}
        assert resp == expected

    def test_send_recv_read_failed(self):
        """Test send_recv when reading from process fails."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None
        client.proc.stdin.write.return_value = None
        client.proc.stdin.flush.return_value = None
        client.proc.stdout.readline.side_effect = OSError("Connection lost")

        resp = client.send_recv("test", {})

        assert resp["error"] == "read_failed"
        assert "Connection lost" in resp["message"]

    def test_send_recv_non_json(self):
        """Test send_recv when process returns invalid JSON."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None
        client.proc.stdin.write.return_value = None
        client.proc.stdin.flush.return_value = None
        client.proc.stdout.readline.return_value = "not json\n"

        resp = client.send_recv("test", {})

        expected = {"error": "non-json", "raw": "not json"}
        assert resp == expected

    def test_send_recv_valid_json(self):
        """Test send_recv with valid JSON response."""
        client = StdioClient.__new__(StdioClient)
        client.proc = Mock()
        client.proc.poll.return_value = None
        client.proc.stdin.write.return_value = None
        client.proc.stdin.flush.return_value = None

        valid_response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        client.proc.stdout.readline.return_value = json.dumps(valid_response) + "\n"

        resp = client.send_recv("tools/list", {})

        assert resp == valid_response


class TestRunChecksStdio:
    """Test the run_checks_stdio function."""

    @pytest.fixture
    def spec_index(self):
        """Fixture providing loaded spec index."""
        return load_spec()

    @pytest.mark.parametrize("error_scenario,expected_detail", [
        (
            # Command fails to start
            "command_failed",
            "Command failed to start"
        ),
        (
            # Process dies during initialize
            {"error": "process_died", "exit_code": 1},
            "MCP server communication failed"
        ),
        (
            # Non-JSON response during initialize
            {"error": "non-json", "raw": "not json"},
            "non-json"
        ),
        (
            # Write failed during initialize
            {"error": "write_failed", "message": "Broken pipe"},
            "write_failed"
        ),
        (
            # No response during initialize
            {"error": "no_response", "message": "Process crashed"},
            "no_response"
        ),
    ])
    @patch('src.mcp_scanner.stdio_scanner.StdioClient')
    def test_early_failure_scenarios(self, mock_stdio_client, spec_index, error_scenario, expected_detail):
        """Test scenarios where scanning fails early and returns only BASE-01 finding."""

        if error_scenario == "command_failed":
            # Command fails to start - StdioClient constructor raises exception
            mock_stdio_client.side_effect = RuntimeError("Command not found")
        else:
            # Process starts but fails during initialize
            mock_client = Mock()
            mock_client.send_recv.return_value = error_scenario
            mock_client.close.return_value = None
            mock_stdio_client.return_value = mock_client

        findings = run_checks_stdio("test-command", spec_index)

        # Should only have BASE-01 finding and return early
        assert len(findings) == 1
        assert findings[0].id == "BASE-01"
        assert not findings[0].passed
        assert expected_detail in findings[0].details

    @patch('src.mcp_scanner.stdio_scanner.StdioClient')
    def test_process_dies_during_tools_list(self, mock_stdio_client, spec_index):
        """Test behavior when process dies during tools/list call."""
        mock_client = Mock()
        # Initialize succeeds, but tools/list fails
        mock_client.send_recv.side_effect = [
            {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},  # initialize
            {"error": "process_died", "exit_code": 1}  # tools/list
        ]
        mock_client.close.return_value = None
        mock_stdio_client.return_value = mock_client

        findings = run_checks_stdio("test-command", spec_index)

        # Should have BASE-01 (passed) and failed tool-related checks
        base_finding = next(f for f in findings if f.id == "BASE-01")
        assert base_finding.passed

        tool_findings = [f for f in findings if f.id in ["X-01", "P-02", "X-03"]]  # A-01 excluded for stdio
        assert len(tool_findings) > 0
        for f in tool_findings:
            assert not f.passed
            assert "Cannot complete check" in f.details


class TestGetStdioHealth:
    """Test the get_stdio_health function."""

    @patch('src.mcp_scanner.stdio_scanner.StdioClient')
    def test_health_check_command_failed(self, mock_stdio_client):
        """Test health check when command fails to start."""
        mock_stdio_client.side_effect = RuntimeError("Command not found")

        health = get_stdio_health("nonexistent-command")

        assert health["target"] == "stdio:nonexistent-command"
        assert health["transport"] == "stdio"
        assert "error" in health
        assert "Failed to start" in health["error"]

    @patch('src.mcp_scanner.stdio_scanner.StdioClient')
    def test_health_check_process_error(self, mock_stdio_client):
        """Test health check when process communication fails."""
        mock_client = Mock()
        mock_client.send_recv.return_value = {"error": "process_died", "exit_code": 1}
        mock_client.close.return_value = None
        mock_stdio_client.return_value = mock_client

        health = get_stdio_health("test-command")

        assert health["target"] == "stdio:test-command"
        assert "error" in health
        assert "Communication failed" in health["error"]

    @patch('src.mcp_scanner.stdio_scanner.StdioClient')
    def test_health_check_success(self, mock_stdio_client):
        """Test successful health check."""
        mock_client = Mock()
        mock_client.send_recv.side_effect = [
            {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},  # initialize
            {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "test"}]}},  # tools/list
            {"jsonrpc": "2.0", "id": 1, "result": {"prompts": []}},  # prompts/list
            {"jsonrpc": "2.0", "id": 1, "result": {"resources": []}}  # resources/list
        ]
        mock_client.close.return_value = None
        mock_stdio_client.return_value = mock_client

        health = get_stdio_health("test-command")

        assert health["target"] == "stdio:test-command"
        assert health["transport"] == "stdio"
        assert "error" not in health
        assert len(health["tools"]) == 1
        assert health["tools"][0]["name"] == "test"


class TestScanStdio:
    """Test the scan_stdio function."""

    @patch('src.mcp_scanner.stdio_scanner.run_checks_stdio')
    def test_scan_stdio_returns_report(self, mock_run_checks):
        """Test that scan_stdio returns a proper Report object."""
        # Mock findings
        mock_run_checks.return_value = []

        result = scan_stdio("test-command", {})

        assert isinstance(result, Report)
        assert result.target == "stdio:test-command"
        mock_run_checks.assert_called_once()


class TestStdioIntegration:
    """Integration tests using a real mock MCP server process."""

    @pytest.fixture
    def mock_mcp_server_script(self):
        """Create a temporary mock MCP server script for testing."""
        script_content = '''#!/usr/bin/env python3
import json
import sys

def main():
    while True:
        try:
            line = input()
            request = json.loads(line)

            method = request.get("method")
            response = {"jsonrpc": "2.0", "id": request.get("id", 1)}

            if method == "initialize":
                response["result"] = {"capabilities": {"tools": {}}}
            elif method == "tools/list":
                response["result"] = {
                    "tools": [
                        {
                            "name": "exec_command",
                            "description": "Execute shell commands",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {"type": "string"}
                                }
                            }
                        }
                    ]
                }
            elif method == "resources/list":
                response["result"] = {"resources": []}
            elif method == "resources/read":
                response["error"] = {"code": -32602, "message": "Invalid params"}
            elif method == "tools/call":
                response["result"] = {"content": [{"type": "text", "text": "Command executed"}]}
            else:
                response["error"] = {"code": -32601, "message": "Method not found"}

            print(json.dumps(response))

        except EOFError:
            break
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32603, "message": f"Internal error: {e}"}
            }
            print(json.dumps(error_response))

if __name__ == "__main__":
    main()
'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            f.flush()
            os.chmod(f.name, 0o755)
            yield f.name

        # Cleanup
        os.unlink(f.name)

    def test_integration_scan_with_mock_server(self, mock_mcp_server_script):
        """Test full integration scan with real mock MCP server."""
        spec_index = load_spec()
        cmd = f"python {mock_mcp_server_script}"

        findings = run_checks_stdio(cmd, spec_index)

        # Should have findings for 10 security checks (A-01 skipped for stdio transport)
        assert len(findings) == 10

        # Check that we have the expected check IDs (A-01 excluded for stdio)
        check_ids = {f.id for f in findings}
        expected_ids = {"BASE-01", "X-01", "P-02", "X-03", "R-01", "R-02", "R-03", "X-02", "A-03", "P-03"}
        assert check_ids == expected_ids

        # A-01 should be skipped (not applicable to local stdio transport)
        assert "A-01" not in check_ids

        # BASE-01 should pass (server responds to initialize)
        base_finding = next(f for f in findings if f.id == "BASE-01")
        assert base_finding.passed

        # X-01 should fail (dangerous tool without constraints)
        danger_finding = next(f for f in findings if f.id == "X-01")
        assert not danger_finding.passed

    def test_integration_health_check(self, mock_mcp_server_script):
        """Test health check integration with real mock MCP server."""
        cmd = f"python {mock_mcp_server_script}"

        health = get_stdio_health(cmd)

        assert health["target"] == f"stdio:{cmd}"
        assert health["transport"] == "stdio"
        assert "error" not in health
        assert "initialize" in health
        assert "capabilities" in health["initialize"]["result"]
        assert len(health["tools"]) == 1
        assert health["tools"][0]["name"] == "exec_command"
        assert len(health["prompts"]) == 0
        assert len(health["resources"]) == 0

    def test_integration_invalid_command(self):
        """Test integration with invalid command."""
        spec_index = load_spec()

        findings = run_checks_stdio("nonexistent-command-12345", spec_index)

        # Should have only BASE-01 finding that failed
        assert len(findings) == 1
        assert findings[0].id == "BASE-01"
        assert not findings[0].passed
        assert "Command failed to start" in findings[0].details

    def test_integration_health_check_invalid_command(self):
        """Test health check with invalid command."""
        health = get_stdio_health("nonexistent-command-12345")

        assert health["target"] == "stdio:nonexistent-command-12345"
        assert health["transport"] == "stdio"
        assert "error" in health
        assert "Failed to start" in health["error"]

    @pytest.fixture
    def crashing_server_script(self):
        """Create a mock server that crashes immediately."""
        script_content = '''#!/usr/bin/env python3
import sys
sys.exit(1)
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            f.flush()
            os.chmod(f.name, 0o755)
            yield f.name

        os.unlink(f.name)

    def test_integration_crashing_server(self, crashing_server_script):
        """Test integration with server that crashes immediately."""
        spec_index = load_spec()
        cmd = f"python {crashing_server_script}"

        findings = run_checks_stdio(cmd, spec_index)

        # Should have only BASE-01 finding that failed
        assert len(findings) == 1
        assert findings[0].id == "BASE-01"
        assert not findings[0].passed
        assert "exited immediately" in findings[0].details

    @pytest.fixture
    def non_json_server_script(self):
        """Create a mock server that returns non-JSON responses."""
        script_content = '''#!/usr/bin/env python3
import sys

# Just echo back whatever we receive, not JSON
while True:
    try:
        line = input()
        print("This is not JSON")
    except EOFError:
        break
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            f.flush()
            os.chmod(f.name, 0o755)
            yield f.name

        os.unlink(f.name)

    def test_integration_non_json_server(self, non_json_server_script):
        """Test integration with server that returns non-JSON."""
        spec_index = load_spec()
        cmd = f"python {non_json_server_script}"

        findings = run_checks_stdio(cmd, spec_index)

        # Should have only BASE-01 finding that failed
        assert len(findings) == 1
        assert findings[0].id == "BASE-01"
        assert not findings[0].passed
        assert "non-json" in findings[0].details


if __name__ == "__main__":
    pytest.main([__file__, "-v"])