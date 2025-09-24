"""
Common security check implementations that can be shared across all transports.

This module contains transport-agnostic security check logic that can be used by
stdio, HTTP, and other custom implementations. Each function takes
the necessary data and returns a Finding object.

Design principles:
- Transport agnostic: No knowledge of how data was obtained
- Pure functions: Given same input, always return same output
- Dependency injection: Transport-specific functions passed as parameters
- Easy adoption: HTTP scanner can adopt these without breaking changes
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Callable, Optional

from .models import Finding, Severity
from .spec import SpecCheck


def _finding(spec: SpecCheck, passed: bool, details: str) -> Finding:
    """Helper to create a Finding object from check results."""
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


def check_unauthenticated_access(tools: List[Dict[str, Any]], spec: SpecCheck) -> Finding:
    """
    A-01: Authentication required for remote servers.

    Check if tools are accessible without authentication.
    For remote servers, no tools should be available without auth.
    """
    passed = not bool(tools)
    details = json.dumps({"tools_count": len(tools), "tools": tools})
    return _finding(spec, passed, details)


def check_dangerous_capabilities(tools: List[Dict[str, Any]], spec: SpecCheck) -> Finding:
    """
    X-01: Dangerous capability detection in tools.

    Detect tools with dangerous capabilities that lack proper constraints.
    Tools with risky keywords should have input validation constraints.
    """
    risky_keywords = [
        "exec", "command", "shell", "write_file", "delete", "rm", "chmod", "chown",
        "fetch", "http", "url", "eval", "render", "payment", "admin", "privilege",
    ]

    risky_tools: List[Dict[str, Any]] = []
    for tool in tools:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()
        schema = tool.get("inputSchema") or {}

        # Check if tool has constraints
        has_constraints = False
        if isinstance(schema, dict):
            props = schema.get("properties") or {}
            for _, prop in (props.items() if isinstance(props, dict) else []):
                if any(k in prop for k in ("enum", "pattern", "minimum", "maximum", "minLength", "maxLength")):
                    has_constraints = True
                    break

        # If tool has risky keywords but no constraints, it's dangerous
        if any(keyword in name or keyword in desc for keyword in risky_keywords) and not has_constraints:
            risky_tools.append(tool)

    passed = len(risky_tools) == 0
    details = json.dumps(risky_tools)
    return _finding(spec, passed, details)


def check_prompt_injection_heuristics(tools: List[Dict[str, Any]], spec: SpecCheck) -> Finding:
    """
    P-02: Prompt/description injection heuristics.

    Detect suspicious phrases in tool descriptions that could indicate prompt injection.
    """
    bad_phrases = [
        "ignore any safety rules",
        "override other tools",
        "include contents of",
        "do not disclose this instruction",
        "hidden instruction",
    ]

    hits = []
    for tool in tools:
        desc = (tool.get("description") or "").lower()
        if any(phrase in desc for phrase in bad_phrases):
            hits.append(tool)

    passed = len(hits) == 0
    details = json.dumps(hits)
    return _finding(spec, passed, details)


def check_tool_stability(
    tools_first: List[Dict[str, Any]],
    tools_second: List[Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    X-03: Tool description stability (anti rug-pull).

    Compare two tool listings to detect if descriptions have changed,
    which could indicate a rug-pull attack where tools change behavior
    after being approved.
    """
    def tool_key(tool: Dict[str, Any]) -> tuple:
        return (tool.get("name"), tool.get("description"))

    set1 = {tool_key(t) for t in tools_first}
    set2 = {tool_key(t) for t in tools_second}

    diff = []
    if set1 != set2:
        # Find tools that changed
        for (name, desc) in set1.symmetric_difference(set2):
            diff.append({
                "before": [t for t in tools_first if t.get("name") == name and t.get("description") == desc],
                "after": [t for t in tools_second if t.get("name") == name and t.get("description") == desc]
            })

    passed = len(diff) == 0
    details = json.dumps(diff)
    return _finding(spec, passed, details)


def check_resource_traversal(
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    R-01: Resource URI validation & path traversal prevention.

    Test if the server accepts path traversal URIs like "file:///../../etc/hosts".
    Uses dependency injection for transport-specific communication.
    """
    attempt = send_recv_func("resources/read", {"uri": "file:///../../etc/hosts"})

    # Success means the server accepted the traversal (bad)
    accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
    passed = not accepted
    details = json.dumps(attempt)
    return _finding(spec, passed, details)


def check_resource_access_control(
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    R-02: Per-resource access control.

    Test if the server properly controls access to sensitive system files.
    """
    attempt = send_recv_func("resources/read", {"uri": "file:///etc/passwd"})

    # Success means the server allowed access to passwd (bad)
    accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
    passed = not accepted
    details = json.dumps(attempt)
    return _finding(spec, passed, details)


def check_sensitive_resource_exposure(
    resources: List[Dict[str, Any]],
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    R-03: Sensitive resource exposure.

    Check if any listed resources contain sensitive keywords that could
    indicate exposed credentials, secrets, or other sensitive data.
    Also reads suspicious resources to examine their content.
    """
    sensitive_keywords = ["credential", "secret", "token", "key", "password"]
    suspects = []

    for resource in resources:
        name = (resource.get("name") or "").lower()
        uri = (resource.get("uri") or "").lower()
        if any(keyword in name or keyword in uri for keyword in sensitive_keywords):
            if resource.get("uri"):
                # Actually read the resource to examine its content
                resp = send_recv_func("resources/read", {"uri": resource["uri"]})
                text = json.dumps(resp).lower()
                # Check for additional sensitive content indicators
                content_indicators = ["password", "apikey", "api key", "sk-", "postgresql://", "username:"]
                if any(indicator in text for indicator in content_indicators):
                    suspects.append({"resource": resource, "resp": resp})
                # Note: If resource has suspicious name but clean content, we don't flag it
                # This matches the HTTP implementation behavior
            else:
                # Resource has suspicious name but no URI to read - always flag this
                suspects.append({"resource": resource, "resp": None})

    passed = len(suspects) == 0
    details = json.dumps(suspects)
    return _finding(spec, passed, details)


def check_injection_fuzzing(
    tools: List[Dict[str, Any]],
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    X-02: Input validation & injection fuzzing.

    Test tools with injection payloads to see if they execute dangerous commands
    or leak system information.
    """
    payloads = [
        "; id",
        "$(whoami)",
        "`uname -a`",
        "../../../../etc/passwd",
        "http://169.254.169.254/latest/meta-data/"
    ]

    observed_danger = []
    for tool in tools:
        name = tool.get("name")
        schema = tool.get("inputSchema") or {}
        props = schema.get("properties") or {}

        # Find a string parameter to test
        str_param = None
        for param_name, param_def in (props.items() if isinstance(props, dict) else []):
            if param_def.get("type") == "string":
                str_param = param_name
                break

        if not (name and str_param):
            continue

        # Test each payload
        for payload in payloads:
            resp = send_recv_func("tools/call", {
                "name": name,
                "arguments": {str_param: payload}
            })

            # Check if response contains system information (dangerous)
            text = json.dumps(resp).lower()
            danger_indicators = ["uid=", "linux", "root:x:", "etc/passwd", "meta-data", "insecure", "stdout"]
            if any(indicator in text for indicator in danger_indicators):
                observed_danger.append({
                    "tool": name,
                    "payload": payload,
                    "resp": resp
                })
                break  # Stop testing this tool after first dangerous response

    passed = len(observed_danger) == 0
    details = json.dumps(observed_danger)
    return _finding(spec, passed, details)


def check_token_passthrough(
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    A-03: Token indirection (no upstream token pass-through).

    Test if the server leaks upstream access tokens through tool responses.
    """
    # Try to call a tool that might expose tokens
    leak_attempt = send_recv_func("tools/call", {
        "name": "upstream_access",
        "arguments": {"code": "dummy"}
    })

    text = json.dumps(leak_attempt).lower()
    token_indicators = ["access_token", "sk-", "token-body", "bearer "]
    leaked = any(indicator in text for indicator in token_indicators)

    passed = not leaked
    details = json.dumps(leak_attempt)
    return _finding(spec, passed, details)


def check_indirect_prompt_injection(
    resources: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    send_recv_func: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    spec: SpecCheck
) -> Finding:
    """
    P-03: Indirect prompt injection via external resources.

    Check if external resources contain prompt injection attempts and if
    resource summarization exposes these injections. Checks external://,
    http://, and https:// resources.
    """
    p03_hits: List[Dict[str, Any]] = []

    try:
        # Identify external-like resources (matches HTTP implementation)
        external_candidates = [
            r for r in (resources or [])
            if isinstance(r, dict) and isinstance(r.get("uri"), str)
            and (
                r["uri"].startswith("external://")
                or r["uri"].startswith("http://")
                or r["uri"].startswith("https://")
            )
        ]

        # Comprehensive injection patterns (matches HTTP implementation)
        inj_patterns = [
            "ignore previous instructions",
            "do not disclose",
            "exfiltrate",
            "send secrets",
            "hidden instruction",
            "override",
            "leak",
        ]

        # Find a summarize-like tool dynamically (matches HTTP implementation)
        summarize_tool: Optional[str] = None
        for t in tools or []:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            if any(k in name for k in ["summarize", "summary"]) or any(k in desc for k in ["summarize", "summary"]):
                summarize_tool = t.get("name")
                break

        for r in external_candidates:
            uri = r.get("uri")
            read_resp = send_recv_func("resources/read", {"uri": uri})
            text = json.dumps(read_resp).lower()
            suspicious = any(p in text for p in inj_patterns)
            exploited = False
            summary_resp: Any = None

            if summarize_tool:
                try:
                    summary_resp = send_recv_func("tools/call", {"name": summarize_tool, "arguments": {"uri": uri}})
                    stext = json.dumps(summary_resp).lower()
                    if any(p in stext for p in inj_patterns) or any(k in stext for k in ["secret", "token", "password"]):
                        exploited = True
                except Exception:
                    pass

            if suspicious or exploited:
                p03_hits.append({
                    "resource": r,
                    "suspicious": suspicious,
                    "exploited": exploited,
                    "resource_read": read_resp,
                    "summary": summary_resp,
                })

        passed = len(p03_hits) == 0
        details = json.dumps(p03_hits)
        return _finding(spec, passed, details)

    except Exception as e:
        return _finding(spec, passed=False, details=f"error={type(e).__name__}:{e}")