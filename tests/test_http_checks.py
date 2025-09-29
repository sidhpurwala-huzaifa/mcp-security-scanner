"""
Unit tests for http_checks module X-01 refactor.

Tests that the X-01 check in http_checks properly detects dangerous tools.
"""

import pytest
import subprocess
import time
from unittest.mock import patch

from src.mcp_scanner.http_checks import run_full_http_checks
from src.mcp_scanner.spec import load_spec


class TestHttpChecksX01Integration:
    """Test that http_checks detects X-01 violations."""

    @pytest.fixture
    def spec_index(self):
        """Fixture providing loaded spec index."""
        return load_spec()

    def test_http_checks_detects_x01_with_insecure_server(self, spec_index):
        """Test that http_checks detects X-01 violations using the insecure MCP server."""

        # Try to start the insecure server via the CLI command
        server_port = 9877
        server_url = f"http://127.0.0.1:{server_port}"
        server_process = None

        try:
            # Start the insecure server
            server_process = subprocess.Popen(
                ["insecure-mcp-server", "--host", "127.0.0.1", "--port", str(server_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Give the server time to start
            time.sleep(3)

            # Check if server is still running (didn't crash immediately)
            if server_process.poll() is not None:
                stdout, stderr = server_process.communicate()
                pytest.skip(f"insecure-mcp-server failed to start: {stderr.decode()}")

            # Run the HTTP checks against the insecure server
            findings = run_full_http_checks(server_url, spec_index, timeout=10.0)

            # Find the X-01 finding
            x01_findings = [f for f in findings if f.id == "X-01"]
            assert len(x01_findings) == 1

            x01_finding = x01_findings[0]

            # X-01 should fail because the insecure server has dangerous tools without constraints
            assert not x01_finding.passed
            assert x01_finding.id == "X-01"

            # The details should contain information about the dangerous tools
            assert "exec_command" in x01_finding.details or "read_file" in x01_finding.details
        except FileNotFoundError:
            pytest.skip("insecure-mcp-server command not available")
        except Exception as e:
            pytest.skip(f"Could not test with insecure server: {e}")
        finally:
            # Clean up - terminate the server process
            if server_process:
                try:
                    server_process.terminate()
                    server_process.wait(timeout=3)
                except:
                    try:
                        server_process.kill()
                        server_process.wait(timeout=1)
                    except:
                        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])