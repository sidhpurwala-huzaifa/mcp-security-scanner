from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

from . import security_checks
from .models import Finding, Report, Severity
from .spec import SpecCheck


def _finding(spec: SpecCheck, passed: bool, details: str) -> Finding:
    return Finding(
        id=spec.id,
        title=spec.title,
        category=spec.category,
        severity=Severity(spec.severity),
        passed=passed,
        details=details,
        remediation=spec.remediation,
        references=spec.references,
    )


class StdioClient:
    def __init__(self, cmd: str) -> None:
        import time

        self.cmd = cmd
        args = shlex.split(cmd)

        try:
            self.proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as e:
            raise RuntimeError(f"Command not found: {args[0]}. Error: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to start command '{cmd}': {e}")

        # Give the process a moment to start and check if it's still running
        time.sleep(0.1)
        if self.proc.poll() is not None:
            stderr_output = ""
            if self.proc.stderr:
                stderr_output = self.proc.stderr.read()
            raise RuntimeError(
                f"Command '{cmd}' exited immediately with code {self.proc.returncode}. Stderr: {stderr_output}"
            )

    def send_recv(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Send JSON-RPC request to MCP server and receive response.

        Returns either:
        - Valid JSON-RPC response from the server
        - Custom error response indicating transport/process failure

        Custom Error Codes (not standard JSON-RPC):
        - "process_died": MCP server process has exited
        - "stdio_unavailable": stdin/stdout pipes are not accessible
        - "write_failed": Failed to send data to server process
        - "read_failed": Failed to read response from server process
        - "no_response": Server returned no data (likely crashed)
        - "non-json": Server sent invalid JSON response

        These custom codes help distinguish transport failures from MCP protocol errors.
        """
        # Check if process is still alive
        if self.proc.poll() is not None:
            stderr_output = ""
            if self.proc.stderr:
                stderr_output = self.proc.stderr.read()
            return {
                "error": "process_died",
                "exit_code": self.proc.returncode,
                "stderr": stderr_output,
            }

        if self.proc.stdin is None or self.proc.stdout is None:
            return {"error": "stdio_unavailable", "message": "stdin/stdout pipes not available"}

        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        line = json.dumps(req) + "\n"

        try:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            return {"error": "write_failed", "message": f"Failed to write to process: {e}"}

        try:
            resp_line = self.proc.stdout.readline()
            if not resp_line:  # EOF - process likely died
                return {
                    "error": "no_response",
                    "message": "Process returned no data (likely crashed)",
                }
        except Exception as e:
            return {"error": "read_failed", "message": f"Failed to read from process: {e}"}

        try:
            return json.loads(resp_line)
        except json.JSONDecodeError:
            return {"error": "non-json", "raw": resp_line.strip()}

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
        except Exception:
            pass  # Ignore errors during cleanup
        finally:
            try:
                self.proc.terminate()
                # Give it a moment to terminate gracefully
                import time

                time.sleep(0.1)
                if self.proc.poll() is None:
                    self.proc.kill()  # Force kill if still running
            except Exception:
                pass  # Ignore errors during termination


def _is_process_error(resp: Any) -> bool:
    """
    Check if response indicates a process/communication error (not MCP protocol error).

    Returns True for custom transport error codes that indicate the MCP server process
    or stdio communication has failed, meaning we cannot continue scanning.

    Custom error codes checked:
    - "process_died": Server process has exited
    - "stdio_unavailable": stdin/stdout pipes not accessible
    - "write_failed": Failed to send data to server
    - "read_failed": Failed to read response from server
    - "no_response": Server returned no data (likely crashed)
    - "non-json": Server sent invalid JSON (not a functional MCP server)

    Also returns True for non-dict responses, as they indicate fundamental
    communication failure (server returned completely invalid data).
    """
    # Non-dict responses indicate fundamental communication failure
    if not isinstance(resp, dict):
        return True

    # Check for our custom error codes
    if "error" in resp:
        error_type = resp.get("error")
        return error_type in [
            "process_died",
            "stdio_unavailable",
            "write_failed",
            "read_failed",
            "no_response",
            "non-json",
        ]

    return False


def run_checks_stdio(cmd: str, spec_index: dict[str, SpecCheck]) -> list[Finding]:
    findings: list[Finding] = []

    try:
        client = StdioClient(cmd)
    except RuntimeError as e:
        # Command failed to start - create a finding for this
        base = spec_index.get("BASE-01")
        if base:
            findings.append(_finding(base, False, f"Command failed to start: {e}"))
        return findings

    try:
        # BASE-01: Initialize capability check
        base = spec_index.get("BASE-01")
        if base:
            resp = client.send_recv("initialize", {})

            # Check if we got an error response indicating process issues
            if _is_process_error(resp):
                findings.append(
                    _finding(base, False, f"MCP server communication failed: {json.dumps(resp)}")
                )
                return findings  # Can't continue if server is dead

            ok = (
                isinstance(resp, dict)
                and "result" in resp
                and "capabilities" in resp.get("result", {})
            )
            findings.append(_finding(base, ok, json.dumps(resp)))

        # Get tools list for multiple checks
        tools_list = client.send_recv("tools/list", {})

        # Check if process died during tools/list call
        if _is_process_error(tools_list):
            # Create a failed finding for any remaining check that we can't perform
            # Note: A-01 is skipped for stdio transport as it only applies to remote servers
            for check_id in ["X-01", "P-02", "X-03"]:  # Tool-related checks (excluding A-01)
                check = spec_index.get(check_id)
                if check:
                    findings.append(
                        _finding(
                            check,
                            False,
                            f"Cannot complete check - MCP server died: {json.dumps(tools_list)}",
                        )
                    )
            return findings

        tools = (
            tools_list.get("result", {}).get("tools", []) if isinstance(tools_list, dict) else []
        )

        # =============================================================================
        # SECURITY CHECKS FOR STDIO TRANSPORT
        # =============================================================================
        # Note on check selection for stdio transport:
        #
        # SKIPPED CHECKS:
        # - A-01: Authentication required for remote servers
        #   Reason: stdio is local process communication, authentication N/A
        #
        # INCLUDED CHECKS (with stdio-specific rationale):
        # - All tool-based checks (X-01, P-02, X-03, X-02): Dangerous tools are
        #   dangerous regardless of transport mechanism
        # - Resource checks (R-01, R-02, R-03): Local MCP servers can still access
        #   file systems and should have proper path restrictions
        # - Token checks (A-03): Local servers may call external APIs and leak tokens
        # - Prompt injection (P-03): Local servers can fetch external content
        # =============================================================================

        # A-01: Unauthenticated access - SKIP for stdio transport
        # A-01 is specifically for "remote servers" but stdio is local process communication

        # X-01: Dangerous capability detection
        x01 = spec_index.get("X-01")
        if x01:
            findings.append(security_checks.check_dangerous_capabilities(tools, x01))

        # P-02: Prompt/description injection heuristics
        p02 = spec_index.get("P-02")
        if p02:
            findings.append(security_checks.check_prompt_injection_heuristics(tools, p02))

        # X-03: Tool description stability (anti rug-pull)
        x03 = spec_index.get("X-03")
        if x03:
            tools_list2 = client.send_recv("tools/list", {})
            tools2 = (
                tools_list2.get("result", {}).get("tools", [])
                if isinstance(tools_list2, dict)
                else []
            )
            findings.append(security_checks.check_tool_stability(tools, tools2, x03))

        # R-01: Resource traversal
        r01 = spec_index.get("R-01")
        if r01:
            findings.append(security_checks.check_resource_traversal(client.send_recv, r01))

        # R-02: Per-resource access control
        r02 = spec_index.get("R-02")
        if r02:
            findings.append(security_checks.check_resource_access_control(client.send_recv, r02))

        # R-03: Sensitive resource exposure
        r03 = spec_index.get("R-03")
        if r03:
            res_list = client.send_recv("resources/list", {})
            resources = (
                res_list.get("result", {}).get("resources", [])
                if isinstance(res_list, dict)
                else []
            )
            findings.append(
                security_checks.check_sensitive_resource_exposure(resources, client.send_recv, r03)
            )

        # X-02: Injection fuzzing
        x02 = spec_index.get("X-02")
        if x02:
            findings.append(security_checks.check_injection_fuzzing(tools, client.send_recv, x02))

        # A-03: Token pass-through exposure
        # NOTE: While primarily designed for remote servers, this check is still relevant
        # for stdio transport. Local MCP servers may call external APIs (GitHub, OpenAI, etc.)
        # and could accidentally leak API tokens/credentials in tool responses. Examples:
        # - Local git server leaking GitHub personal access tokens
        # - Local web server exposing API keys in error messages
        # - Development tools accidentally including bearer tokens in output
        a03 = spec_index.get("A-03")
        if a03:
            findings.append(security_checks.check_token_passthrough(client.send_recv, a03))

        # P-03: Indirect prompt injection via external resources
        p03 = spec_index.get("P-03")
        if p03:
            res_list = client.send_recv("resources/list", {})
            resources = (
                res_list.get("result", {}).get("resources", [])
                if isinstance(res_list, dict)
                else []
            )
            findings.append(
                security_checks.check_indirect_prompt_injection(
                    resources, tools, client.send_recv, p03
                )
            )

    finally:
        client.close()

    return findings


def get_stdio_health(cmd: str) -> dict[str, Any]:
    """Get health information from stdio MCP server (similar to HTTP health check)"""
    health = {
        "target": f"stdio:{cmd}",
        "transport": "stdio",
        "initialize": {},
        "tools": [],
        "prompts": [],
        "resources": [],
    }

    try:
        client = StdioClient(cmd)
    except RuntimeError as e:
        health["error"] = f"Failed to start: {e}"
        return health

    try:
        # Initialize
        init_resp = client.send_recv("initialize", {})
        health["initialize"] = init_resp

        # Early exit if process died
        if _is_process_error(init_resp):
            health["error"] = f"Communication failed: {init_resp}"
            return health

        # Tools
        tools_resp = client.send_recv("tools/list", {})
        if not _is_process_error(tools_resp):
            health["tools"] = tools_resp.get("result", {}).get("tools", [])

        # Prompts
        prompts_resp = client.send_recv("prompts/list", {})
        if not _is_process_error(prompts_resp):
            health["prompts"] = prompts_resp.get("result", {}).get("prompts", [])

        # Resources
        resources_resp = client.send_recv("resources/list", {})
        if not _is_process_error(resources_resp):
            health["resources"] = resources_resp.get("result", {}).get("resources", [])

    except Exception as e:
        health["error"] = f"Unexpected error: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass

    return health


def scan_stdio(cmd: str, spec_index: dict[str, SpecCheck]) -> Report:
    findings = run_checks_stdio(cmd, spec_index)
    return Report.new(target=f"stdio:{cmd}", findings=findings)
