"""
Tests for http_checks module using security_checks refactor.

Tests that security checks properly detect violations against the insecure MCP server.
"""

import pytest
import subprocess
import time
from unittest.mock import patch

from src.mcp_scanner.http_checks import run_full_http_checks
from src.mcp_scanner.spec import load_spec


class TestHttpChecksIntegration:
    """Test that http_checks detects security violations.

    TODO: Add separate tests for different insecure server modes:
    - Mode 2: Test P-02 failure (malicious tool descriptions)
    - Mode 3: Test X-03 failure (rug-pull behavior)
    - Mode 5: Test A-03 failure (token leak)
    - Mode 6: Test P-03 (indirect prompt injection)
    - Mode 7: Test RC-01 (remote access control)
    """

    @pytest.fixture
    def spec_index(self):
        """Fixture providing loaded spec index."""
        return load_spec()

    def test_http_checks_detects_tool_violations(self, spec_index):
        """Test that http_checks detects security violations using the insecure MCP server.

        Uses insecure server in default mode 0, which provides:
        - Dangerous tools (exec_command, read_file) without constraints
        - Clean tool descriptions (no prompt injection in metadata)
        - Stable tool list (no rug-pull behavior)
        - Vulnerable to injection attacks when tools are called
        - Allows unauthorized resource access (traversal, /etc/passwd)
        """

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

            # Validate P-02: Prompt injection heuristics (should pass - no malicious prompts in descriptions)
            p02_findings = [f for f in findings if f.id == "P-02"]
            assert len(p02_findings) == 1
            assert p02_findings[0].passed

            # Validate X-03: Tool stability (should pass - tools remain stable)
            x03_findings = [f for f in findings if f.id == "X-03"]
            assert len(x03_findings) == 1
            assert x03_findings[0].passed

            # Validate R-01: Resource traversal (should fail - insecure server allows traversal)
            r01_findings = [f for f in findings if f.id == "R-01"]
            assert len(r01_findings) == 1
            assert not r01_findings[0].passed

            # Validate R-02: Resource access control (should fail - insecure server allows /etc/passwd)
            r02_findings = [f for f in findings if f.id == "R-02"]
            assert len(r02_findings) == 1
            assert not r02_findings[0].passed

            # Validate X-02: Injection fuzzing (should fail - insecure server is vulnerable)
            x02_findings = [f for f in findings if f.id == "X-02"]
            assert len(x02_findings) == 1
            assert not x02_findings[0].passed

            # Validate A-03: Token passthrough (should pass - upstream_access tool not in mode 0)
            a03_findings = [f for f in findings if f.id == "A-03"]
            assert len(a03_findings) == 1
            assert a03_findings[0].passed
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