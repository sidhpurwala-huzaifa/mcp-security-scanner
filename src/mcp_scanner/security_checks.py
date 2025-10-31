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
from collections.abc import Callable
from typing import Any, Dict, Iterable, List

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


def check_unauthenticated_access(tools: list[dict[str, Any]], spec: SpecCheck) -> Finding:
    """
    A-01: Authentication required for remote servers.

    Check if tools are accessible without authentication.
    For remote servers, no tools should be available without auth.
    """
    passed = not bool(tools)
    details = json.dumps({"tools_count": len(tools), "tools": tools})
    return _finding(spec, passed, details)


def _to_lower(value: Any) -> str:
    """Best-effort lower-casing helper that tolerates non-string input."""

    if isinstance(value, str):
        return value.lower()
    return ""


def _schema_properties(schema: Any) -> dict[str, Any]:
    """Return the JSON schema properties dictionary if present."""

    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if isinstance(props, dict):
        return props
    # Some schemas omit the explicit object type but still provide properties
    if schema.get("type") == "object":
        return props or {}
    return {}


def _schema_required(schema: Any) -> set[str]:
    """Extract the required parameter names from the schema."""

    if isinstance(schema, dict):
        required = schema.get("required")
        if isinstance(required, list):
            return {name for name in required if isinstance(name, str)}
    return set()


def _type_matches(definition: dict[str, Any], expected: str) -> bool:
    """Check whether the definition declares the expected JSON type."""

    declared = definition.get("type")
    if isinstance(declared, str):
        return declared == expected
    if isinstance(declared, list):
        return expected in declared
    return False


def _has_guardrails(definition: dict[str, Any]) -> bool:
    """Determine whether a parameter definition has meaningful constraints."""

    if not isinstance(definition, dict):
        return False

    # Structural constraints count as guardrails
    structural_keys = {"anyOf", "allOf", "oneOf", "if", "then", "else", "not", "dependentSchemas"}
    if any(key in definition for key in structural_keys):
        return True

    constraint_keys: set[str]
    if _type_matches(definition, "string"):
        constraint_keys = {
            "enum",
            "const",
            "pattern",
            "format",
            "contentEncoding",
            "contentMediaType",
            "minLength",
            "maxLength",
        }
    elif _type_matches(definition, "integer") or _type_matches(definition, "number"):
        constraint_keys = {"enum", "const", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"}
    elif _type_matches(definition, "boolean"):
        constraint_keys = {"enum", "const"}
    elif _type_matches(definition, "array"):
        constraint_keys = {"enum", "const", "items", "minItems", "maxItems"}
    else:
        # Objects or unknown types – treat presence of enum/const as a constraint.
        constraint_keys = {"enum", "const"}

    return any(key in definition for key in constraint_keys)


def _risk_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    """Return the subset of keywords found in the provided text."""

    lowered = text.lower()
    return sorted({kw for kw in keywords if kw in lowered})


def check_dangerous_capabilities(tools: list[dict[str, Any]], spec: SpecCheck) -> Finding:
    """
    X-01: Dangerous capability detection in tools.

    Detect tools with dangerous capabilities that lack proper constraints.
    Tools with risky keywords should have input validation constraints.
    """
    risky_keywords = {
        "exec",
        "command",
        "shell",
        "write_file",
        "delete",
        "rm",
        "chmod",
        "chown",
        "fetch",
        "http",
        "url",
        "eval",
        "render",
        "payment",
        "admin",
        "privilege",
    }
    risky_parameter_keywords = {
        "command",
        "cmd",
        "script",
        "shell",
        "path",
        "filepath",
        "file_path",
        "file",
        "uri",
        "url",
        "payload",
        "prompt",
        "query",
        "template",
        "body",
        "code",
        "sql",
    }

    metadata_risk_flags = {"dangerous", "allowDangerousOperations", "allowDangerousCommands"}

    risky_tools: list[dict[str, Any]] = []

    for tool in tools or []:
        name = _to_lower(tool.get("name"))
        desc = _to_lower(tool.get("description"))
        schema = tool.get("inputSchema") or {}
        props = _schema_properties(schema)
        required_params = _schema_required(schema)

        name_matches = _risk_keywords(f"{name} {desc}", risky_keywords)
        metadata = tool.get("metadata") or {}
        metadata_matches = [flag for flag in metadata_risk_flags if metadata.get(flag) or metadata.get(flag.lower())]

        tool_reasons: list[dict[str, Any]] = []

        if name_matches and not props:
            tool_reasons.append({
                "kind": "missing_schema",
                "keywords": name_matches,
                "message": "Tool exposes dangerous capabilities but provides no input schema",
            })

        for param_name, definition in props.items():
            if not isinstance(definition, dict):
                continue

            param_keywords = _risk_keywords(param_name, risky_parameter_keywords)
            if not param_keywords:
                param_desc = _to_lower(definition.get("description"))
                param_keywords = _risk_keywords(param_desc, risky_parameter_keywords)

            is_string_like = _type_matches(definition, "string") or _type_matches(definition, "array")

            if (name_matches or metadata_matches or param_keywords) and is_string_like:
                if not _has_guardrails(definition):
                    tool_reasons.append(
                        {
                            "kind": "unconstrained_parameter",
                            "parameter": param_name,
                            "required": param_name in required_params,
                            "keywords": param_keywords or name_matches,
                            "message": "Parameter accepts attacker-controlled strings without constraints",
                        }
                    )

        if metadata_matches:
            tool_reasons.append(
                {
                    "kind": "metadata_flag",
                    "flags": metadata_matches,
                    "message": "Tool metadata advertises dangerous behavior",
                }
            )

        if tool_reasons:
            risky_tools.append(
                {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "reasons": tool_reasons,
                }
            )

    passed = len(risky_tools) == 0
    details = json.dumps(risky_tools)
    return _finding(spec, passed, details)


def check_prompt_injection_heuristics(tools: list[dict[str, Any]], spec: SpecCheck) -> Finding:
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

    hits: List[Dict[str, object]] = []
    for tool in tools:
        desc = (tool.get("description") or "").lower()
        if any(phrase in desc for phrase in bad_phrases):
            hits.append(tool)

    passed = len(hits) == 0
    details = json.dumps(hits)
    return _finding(spec, passed, details)


def check_tool_stability(
    tools_first: list[dict[str, Any]], tools_second: list[dict[str, Any]], spec: SpecCheck
) -> Finding:
    """
    X-03: Tool description stability (anti rug-pull).

    Compare two tool listings to detect if descriptions have changed,
    which could indicate a rug-pull attack where tools change behavior
    after being approved.
    """

    def tool_key(tool: dict[str, Any]) -> tuple:
        return (tool.get("name"), tool.get("description"))

    set1 = {tool_key(t) for t in tools_first}
    set2 = {tool_key(t) for t in tools_second}

    diff = []
    if set1 != set2:
        # Find tools that changed
        for name, desc in set1.symmetric_difference(set2):
            diff.append(
                {
                    "before": [
                        t
                        for t in tools_first
                        if t.get("name") == name and t.get("description") == desc
                    ],
                    "after": [
                        t
                        for t in tools_second
                        if t.get("name") == name and t.get("description") == desc
                    ],
                }
            )

    passed = len(diff) == 0
    details = json.dumps(diff)
    return _finding(spec, passed, details)


def check_resource_traversal(
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
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
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
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
    resources: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
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
                content_indicators = [
                    "password",
                    "apikey",
                    "api key",
                    "sk-",
                    "postgresql://",
                    "username:",
                ]
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
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
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
        "http://169.254.169.254/latest/meta-data/",
    ]

    danger_indicators = [
        "uid=",
        "gid=",
        "linux",
        "root:x:",
        "etc/passwd",
        "meta-data",
        "stdout",
        "stderr",
        "returncode",
        "command executed",
        "execution result",
        "listening on",
        "connected to",
    ]

    observed_danger: list[dict[str, Any]] = []

    for tool in tools or []:
        name = tool.get("name")
        if not name:
            continue

        schema = tool.get("inputSchema") or {}
        props = _schema_properties(schema)

        string_params = [
            param_name
            for param_name, param_def in props.items()
            if isinstance(param_def, dict) and _type_matches(param_def, "string")
        ]

        if not string_params:
            continue

        for param_name in string_params:
            for payload in payloads:
                try:
                    resp = send_recv_func(
                        "tools/call",
                        {"name": name, "arguments": {param_name: payload}},
                    )
                except Exception:
                    # Ignore transport or execution errors; these do not prove vulnerability
                    continue

                text = json.dumps(resp).lower()
                indicator = next((d for d in danger_indicators if d in text), None)
                if indicator:
                    observed_danger.append(
                        {
                            "tool": name,
                            "parameter": param_name,
                            "payload": payload,
                            "indicator": indicator,
                            "resp": resp,
                        }
                    )
                    break
            if observed_danger and observed_danger[-1]["tool"] == name:
                break  # Stop after first dangerous finding per tool

    passed = len(observed_danger) == 0
    details = json.dumps(observed_danger)
    return _finding(spec, passed, details)


def check_token_passthrough(
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]], spec: SpecCheck
) -> Finding:
    """
    A-03: Token indirection (no upstream token pass-through).

    Test if the server leaks upstream access tokens through tool responses.
    """
    # Try to call a tool that might expose tokens
    leak_attempt = send_recv_func(
        "tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}}
    )

    text = json.dumps(leak_attempt).lower()
    token_indicators = ["access_token", "sk-", "token-body", "bearer "]
    leaked = any(indicator in text for indicator in token_indicators)

    passed = not leaked
    details = json.dumps(leak_attempt)
    return _finding(spec, passed, details)


def check_indirect_prompt_injection(
    resources: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    """
    P-03: Indirect prompt injection via external resources.

    Check if external resources contain prompt injection attempts and if
    resource summarization exposes these injections. Checks external://,
    http://, and https:// resources.
    """
    p03_hits: list[dict[str, Any]] = []

    try:
        # Identify external-like resources (matches HTTP implementation)
        external_candidates = [
            r
            for r in (resources or [])
            if isinstance(r, dict)
            and isinstance(r.get("uri"), str)
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
        summarize_tool: str | None = None
        for t in tools or []:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            if any(k in name for k in ["summarize", "summary"]) or any(
                k in desc for k in ["summarize", "summary"]
            ):
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
                    summary_resp = send_recv_func(
                        "tools/call", {"name": summarize_tool, "arguments": {"uri": uri}}
                    )
                    stext = json.dumps(summary_resp).lower()
                    if any(p in stext for p in inj_patterns) or any(
                        k in stext for k in ["secret", "token", "password"]
                    ):
                        exploited = True
                except Exception:
                    pass

            if suspicious or exploited:
                p03_hits.append(
                    {
                        "resource": r,
                        "suspicious": suspicious,
                        "exploited": exploited,
                        "resource_read": read_resp,
                        "summary": summary_resp,
                    }
                )

        passed = len(p03_hits) == 0
        details = json.dumps(p03_hits)
        return _finding(spec, passed, details)

    except Exception as e:
        return _finding(spec, passed=False, details=f"error={type(e).__name__}:{e}")


def check_remote_access_control_exposure(
    tools: list[dict[str, Any]],
    send_recv_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    spec: SpecCheck,
) -> Finding:
    """
    RC-01: Remote access control exposure.

    Check if server exposes tools that enable/disable remote access or open ports
    without strong authorization. Tests for tools with remote access keywords
    and attempts to exploit them.
    """
    if len(tools) == 0:
        return _finding(spec, passed=True, details="No tools were discovered")

    # Look for tools that might enable remote access
    candidates: list[dict[str, Any]] = []
    for tool in tools:
        name = (tool.get("name") or "").lower()
        desc = (tool.get("description") or "").lower()

        # Check for remote access keywords
        remote_keywords_name = ["remote_access", "remote", "port"]
        remote_keywords_desc = ["remote access", "open port", "expose", "bind"]

        if (
            any(keyword in name for keyword in remote_keywords_name)
            or any(keyword in desc for keyword in remote_keywords_desc)
        ):
            candidates.append(tool)

    # Attempt unauthenticated calls to test for remote access exposure
    exploited = []
    for tool in candidates:
        tool_name = tool.get("name")
        if tool_name:
            try:
                # Test with common remote access arguments
                resp = send_recv_func(
                    "tools/call", {"name": tool_name, "arguments": {"port": 8080}}
                )
                text = json.dumps(resp).lower()

                # Check for indicators that remote access was enabled
                success_indicators = [
                    "remote_access_enabled:true",
                    "remote-access:true",
                    "enabled",
                    "listening",
                    "bound to",
                    "server started"
                ]

                if any(indicator in text for indicator in success_indicators):
                    exploited.append({"tool": tool_name, "resp": resp})
            except Exception:
                # Ignore exceptions during testing - tool might not accept these arguments
                continue

    passed = len(exploited) == 0
    details = json.dumps({"candidates": candidates, "exploited": exploited})
    return _finding(spec, passed, details)
