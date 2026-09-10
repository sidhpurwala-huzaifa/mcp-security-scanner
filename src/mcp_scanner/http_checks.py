from __future__ import annotations
from .http_session import HttpSession

from typing import Dict, List, Optional, Any, Tuple
import json
import re

import httpx
from urllib.parse import urlparse

from .models import Finding, Severity, Outcome
from .spec import SpecCheck, load_spec
from . import security_checks


def _set_mcp_http_headers(client: httpx.Client) -> None:
    # HTTPX installs Accept: */* by default, so membership checks and setdefault
    # cannot enforce MCP's required POST response types (issue #14). Assign via
    # HTTPX's case-insensitive Headers to replace user-supplied variants too.
    # SSE GET requests retain their explicit text/event-stream override.
    client.headers["Accept"] = "application/json, text/event-stream"
    client.headers.setdefault("MCP-Protocol-Version", "2025-06-18")


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


def _unevaluated(spec: SpecCheck, status: Outcome, details: str) -> Finding:
    return Finding(
        id=spec.id, title=spec.title, category=spec.category,
        severity=Severity(spec.severity), status=status, details=details,
        remediation=spec.remediation, references=spec.references,
    )


def _diagnostic(text: str, headers: Optional[Dict[str, str]] = None) -> str:
    # Error messages may echo credentials supplied by the caller.
    for name, value in (headers or {}).items():
        if any(word in name.lower() for word in ("authorization", "cookie", "token", "key", "session")) and value:
            text = text.replace(value, "[redacted]")
            if name.lower() == "authorization" and " " in value:
                text = text.replace(value.split(" ", 1)[1], "[redacted]")
    text = re.sub(r"(?i)([?&](?:sessionId|session_id|access_token|token)=)[^&\s]+", r"\1[redacted]", text)
    return re.sub(r"(?i)bearer\s+\S+", "Bearer [redacted]", text)[:500]


class _RedactedTrace:
    """Sanitize transport diagnostics before storing or printing them."""

    def __init__(self, target: Any, headers: Optional[Dict[str, str]]) -> None:
        self.target = target
        self.headers = headers

    def append(self, entry: Dict[str, Any]) -> None:
        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    key: "[redacted]" if str(key).lower() in {
                        "authorization", "proxy-authorization", "cookie", "set-cookie",
                        "mcp-session-id", "session_id", "sessionid", "x-api-key", "access_token",
                    } else redact(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [redact(item) for item in value]
            if isinstance(value, str):
                return _diagnostic(value, self.headers)
            return value
        self.target.append(redact(entry))


def _response_problem(status: Optional[int], data: Any, expected_id: int) -> Optional[str]:
    if status is None:
        return "No HTTP response received"
    prefix = f"HTTP {status}"
    if isinstance(data, dict) and "error" in data:
        return f"{prefix}; JSON-RPC error: {json.dumps(data['error'])}"
    if not 200 <= status < 300:
        return f"{prefix}; request did not succeed"
    if (not isinstance(data, dict) or data.get("jsonrpc") != "2.0"
            or type(data.get("id")) is not int or data.get("id") != expected_id):
        return f"{prefix}; invalid or mismatched JSON-RPC response"
    if not isinstance(data.get("result"), dict):
        return f"{prefix}; missing or invalid result object"
    return None


def _initialization_problem(status: Optional[int], data: Any) -> Optional[str]:
    problem = _response_problem(status, data, 0)
    if problem:
        return problem
    if not isinstance(data["result"].get("capabilities"), dict):
        return f"HTTP {status}; missing or invalid capabilities"
    return None


def _enumeration_problem(status: int, data: Any, key: str) -> Optional[str]:
    problem = _response_problem(status, data, 99)
    if problem:
        return problem
    items = data["result"].get(key)
    identity = "uri" if key == "resources" else "name"
    if not isinstance(items, list) or any(
        not isinstance(item, dict) or not isinstance(item.get(identity), str)
        for item in items
    ):
        return f"HTTP {status}; missing or malformed {key} list"
    for item in items:
        for field in ("description", "name", "uri", "mimeType"):
            if field in item and not isinstance(item[field], str):
                return f"HTTP {status}; malformed {key} {field}"
        if "inputSchema" in item:
            schema = item["inputSchema"]
            if not isinstance(schema, dict):
                return f"HTTP {status}; malformed {key} inputSchema"
            props = schema.get("properties", {})
            required = schema.get("required", [])
            if (not isinstance(props, dict)
                    or any(not isinstance(v, dict) for v in props.values())
                    or not isinstance(required, list)
                    or any(not isinstance(v, str) for v in required)):
                return f"HTTP {status}; malformed {key} inputSchema properties or required"
    if data["result"].get("nextCursor"):
        return f"HTTP {status}; incomplete {key} enumeration (additional pages required)"
    return None


def scan_http_base(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0) -> List[Finding]:
    findings: List[Finding] = []
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )

    # T-02 TLS enforcement & HSTS
    t02 = spec_index.get("T-02")
    if t02:
        is_https = base_url.lower().startswith("https://")
        details = f"scheme={'https' if is_https else 'http'}"
        findings.append(_finding(t02, passed=is_https, details=details))

    # T-01 Origin validation & local bind (DNS-rebind resistance)
    t01 = spec_index.get("T-01")
    if t01:
        try:
            # Probe SSE endpoint existence first (informational)
            sse_url = base_url.rstrip("/") + "/sse"
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url})
            with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r_ok:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "recv", "status": r_ok.status_code, "headers": dict(r_ok.headers)})
                exists = r_ok.status_code < 500
            # Now try forged Origin
            forged_headers = {**({} if headers is None else headers), "Origin": "http://evil.tld"}
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "headers": {"Origin": "http://evil.tld"}})
            with client.stream("GET", sse_url, headers=forged_headers | {"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "headers": dict(r.headers)})
                accepts_cross = r.status_code < 400
            passed = exists and not accepts_cross
            details = f"sse={r_ok.status_code}; forged_origin={r.status_code}"
        except Exception as e:  # noqa: BLE001
            passed = None
            findings.append(_unevaluated(t01, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))
        if passed is not None:
            findings.append(_finding(t01, passed=passed, details=details))

    # KF-03 Unsafe bind address (heuristic) — treat as warn/info (local-only applicability)
    kf03 = spec_index.get("KF-03")
    if kf03:
        try:
            sse_url = base_url.rstrip("/") + "/sse"
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url})
            with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "recv", "status": r.status_code})
            # Do not fail remote/cluster targets on this heuristic; mark as informational warning
            details = f"warn: local-only heuristic; status={r.status_code}"
            findings.append(
                Finding(
                    id=kf03.id,
                    title=kf03.title,
                    category=kf03.category,
                    severity=Severity.info,
                    status=Outcome.skipped,
                    details=details,
                    remediation=kf03.remediation,
                    references=kf03.references,
                )
            )
        except Exception as e:  # noqa: BLE001
            findings.append(
                Finding(
                    id=kf03.id,
                    title=kf03.title,
                    category=kf03.category,
                    severity=Severity.info,
                    status=Outcome.skipped,
                    details=f"warn: local-only heuristic; error={type(e).__name__}:{e}",
                    remediation=kf03.remediation,
                    references=kf03.references,
                )
            )

    client.close()
    return findings


def run_full_http_checks(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> List[Finding]:
    if trace is not None:
        trace = _RedactedTrace(trace, headers)
    findings: List[Finding] = []
    spec_index = dict(spec_index)  # Dependency gating must not mutate the caller.
    init_status: Optional[int] = None
    init_error: Optional[str] = None
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )
    _set_mcp_http_headers(client)
    session = HttpSession(client, base_url, timeout, trace if verbose else None, transport, sse_endpoint)

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        # Endpoint ownership belongs to the initialized session. The internal
        # ID is normalized only after the unique wire ID has been correlated.
        if payload.get("id") == 99:
            status, data = session.call(payload["method"], payload.get("params", {}))
            if isinstance(data, dict) and "id" in data:
                data = {**data, "id": 99}
            return status, data
        return session.exchange(payload)

    def _discover_endpoint() -> Tuple[Optional[str], Dict[str, Any]]:
        nonlocal init_status, init_error
        try:
            init_status, data = session.initialize()
            return session.url, data
        except Exception as exc:
            init_status = session.initialize_status
            init_error = f"HTTP {init_status}; {type(exc).__name__}: {exc}"
            return None, {}

    try:
        # T-02/T-01/KF-03
        findings.extend(scan_http_base(base_url, spec_index, headers=headers, trace=trace, verbose=verbose, timeout=timeout))

        # A-02: OAuth well-known
        a02 = spec_index.get("A-02")
        if a02:
            try:
                wk = client.get(base_url.rstrip("/") + "/.well-known/oauth-authorization-server")
                ok = wk.status_code == 200
                data = {}
                if ok:
                    try:
                        data = wk.json()
                    except Exception:
                        ok = False
                required = ["token_endpoint", "authorization_endpoint"]
                ok = ok and all(k in data for k in required)
                findings.append(_finding(a02, passed=ok, details=f"status={wk.status_code}, keys={list(data.keys())[:5]}"))
            except Exception as e:
                findings.append(_unevaluated(a02, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))

        # Endpoint selection relies solely on provided URLs; skip capability-based refinement
        msg_url_cache, init_obj = _discover_endpoint()
        problem = init_error or _initialization_problem(init_status, init_obj)
        if problem or msg_url_cache is None:
            reason = _diagnostic("initialize: " + (problem or "No endpoint discovered"), headers)
            # Always surface the prerequisite error, even with a custom spec that
            # omits BASE-01; otherwise skipped checks could look like a clean scan.
            base = spec_index.get("BASE-01") or load_spec()["BASE-01"]
            findings.append(_unevaluated(base, Outcome.error, reason))
            dependent_ids = {
                "A-01", "A-03", "T-03", "RC-01", "X-01", "X-02", "X-03",
                "P-01", "P-02", "P-03", "R-01", "R-02", "R-03", "R-04", "R-05",
            }
            for key, check in spec_index.items():
                if key in dependent_ids:
                    findings.append(_unevaluated(check, Outcome.skipped, reason))
            return findings
        # A-01: Unauthenticated access (probe again without auth only if headers were provided)
        a01 = spec_index.get("A-01")
        if a01:
            try:
                status, data = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
                is_denied = status in (401, 403)
                details = f"status={status}, body={(json.dumps(data)[:200] + '...') if isinstance(data, (dict, list)) else (str(data)[:200] + '...')}"
                findings.append(_finding(a01, passed=is_denied, details=details))
            except Exception as e:
                findings.append(_unevaluated(a01, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))

        # T-03: Session identifier handling (best-effort)
        t03 = spec_index.get("T-03")
        if t03:
            try:
                # For legacy SSE sessions, skip tampering to avoid invalidating the server session
                if session.transport == "sse":
                    findings.append(_unevaluated(t03, Outcome.skipped, "Session tampering skipped on legacy SSE transport"))
                else:
                    status_init, _ = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}})
                    sess_ok = status_init < 500
                    bad_headers = httpx.Headers(client.headers)
                    bad_headers["Mcp-Session-Id"] = "tampered-session"
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, "url": msg_url_cache, "note": "altered session id"})
                    with client.stream("POST", msg_url_cache, json={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, headers=bad_headers) as bad:
                        pass  # This probe needs only the status, never an open SSE body.
                    rejects_bad = bad.status_code in (401, 403, 400)
                    findings.append(_finding(t03, passed=(sess_ok and rejects_bad), details=f"bad_status={bad.status_code}"))
            except Exception as e:
                findings.append(_unevaluated(t03, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))

        # rpc using discovered endpoint only
        def rpc(method: str, params: Dict[str, object]) -> Dict[str, object]:
            status, data = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 99, "method": method, "params": params})
            return data if isinstance(data, dict) else {"status": status, "body": data}

        # BASE-01 already done; record it properly
        base = spec_index.get("BASE-01")
        if base:
            ok = isinstance(init_obj, dict) and "result" in init_obj and "capabilities" in init_obj.get("result", {})
            findings.append(_finding(base, ok, json.dumps(init_obj)))

        def enumerate_items(key: str, dependent_ids: Tuple[str, ...]) -> List[Dict[str, Any]]:
            try:
                status, data = _post_json(msg_url_cache, {
                    "jsonrpc": "2.0", "id": 99, "method": key + "/list", "params": {},
                })
                problem = _enumeration_problem(status, data, key)
            except Exception as exc:
                problem = f"{type(exc).__name__}: {exc}"
            if problem:
                reason = _diagnostic(key + "/list: " + problem, headers)
                for check_id in dependent_ids:
                    check = spec_index.pop(check_id, None)
                    if check:
                        findings.append(_unevaluated(check, Outcome.error, reason))
                return []
            return data["result"][key]

        tools = enumerate_items("tools", ("RC-01", "X-01", "X-02", "X-03", "P-02", "P-03"))

        # RC-01: Remote access control exposure
        rc01 = spec_index.get("RC-01")
        if rc01 and isinstance(tools, list):
            if len(tools) == 0:
                findings.append(_unevaluated(rc01, Outcome.skipped, "tools/list succeeded: no applicable tools"))
            else:
                candidates: List[Dict[str, Any]] = []
                for t in tools:
                    name = (t.get("name") or "").lower()
                    desc = (t.get("description") or "").lower()
                    if any(k in name for k in ["remote_access", "remote", "port"]) or any(k in desc for k in ["remote access", "open port", "expose", "bind"]):
                        candidates.append(t)
                # Attempt unauthenticated call if a known name is present
                exploited = []
                for t in candidates:
                    tname = t.get("name")
                    if tname:
                        try:
                            resp = rpc("tools/call", {"name": tname, "arguments": {"port": 8080}})
                            text = json.dumps(resp).lower()
                            if any(s in text for s in ["remote_access_enabled:true", "remote-access:true", "enabled"]):
                                exploited.append({"tool": tname, "resp": resp})
                        except Exception:
                            continue
                findings.append(_finding(rc01, passed=len(exploited) == 0, details=json.dumps({"candidates": candidates, "exploited": exploited})))

        # X-03 Rug-pull
        x03 = spec_index.get("X-03")
        if x03:
            if not tools:
                findings.append(_unevaluated(x03, Outcome.skipped, "tools/list succeeded: no applicable tools"))
            else:
                tools2 = enumerate_items("tools", ("X-03",))
                if "X-03" in spec_index:
                    findings.append(security_checks.check_tool_stability(tools, tools2, x03))

        # P-02 Prompt/description heuristics
        p02 = spec_index.get("P-02")
        if p02 and isinstance(tools, list):
            if len(tools) == 0:
                findings.append(_unevaluated(p02, Outcome.skipped, "tools/list succeeded: no applicable tools"))
            else:
                findings.append(security_checks.check_prompt_injection_heuristics(tools, p02))

        # P-01 Prompt argument validation
        p01 = spec_index.get("P-01")
        if p01:
            p01_issues: List[Dict[str, Any]] = []
            try:
                prompts = enumerate_items("prompts", ("P-01",))
                for pr in prompts or []:
                    name = pr.get("name")
                    schema = pr.get("inputSchema") or {}
                    required = schema.get("required") or []
                    # Probe missing required args
                    if name and isinstance(required, list) and len(required) > 0:
                        bad_call = rpc("prompts/get", {"name": name, "arguments": {}})
                        # Expect an error when required args are missing
                        if isinstance(bad_call, dict) and "result" in bad_call and "error" not in bad_call:
                            p01_issues.append({"prompt": name, "issue": "missing-required-accepted", "resp": bad_call})
                        else:
                            # Also try invalid type for the first required key if we can infer type
                            first_key = required[0]
                            props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
                            expected_type = (props.get(first_key, {}).get("type") if isinstance(props, dict) else None)
                            invalid_value: Any = None
                            if expected_type == "string":
                                invalid_value = 12345
                            elif expected_type == "integer":
                                invalid_value = "not-an-integer"
                            elif expected_type == "boolean":
                                invalid_value = "not-a-bool"
                            elif expected_type == "array":
                                invalid_value = {"not": "array"}
                            elif expected_type == "object":
                                invalid_value = "not-an-object"
                            else:
                                invalid_value = None
                            if invalid_value is not None:
                                bad_args = {first_key: invalid_value}
                                bad_call2 = rpc("prompts/get", {"name": name, "arguments": bad_args})
                                if isinstance(bad_call2, dict) and "result" in bad_call2 and "error" not in bad_call2:
                                    p01_issues.append({"prompt": name, "issue": "invalid-type-accepted", "resp": bad_call2})
                # If no prompts are present, treat as pass (nothing to validate)
                if "P-01" in spec_index:
                    findings.append(_finding(p01, passed=len(p01_issues) == 0, details=json.dumps(p01_issues)) if prompts else _unevaluated(p01, Outcome.skipped, "prompts/list succeeded: no applicable prompts"))
            except Exception as e:
                findings.append(_unevaluated(p01, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))

        # X-01 risky unconstrained tools
        x01 = spec_index.get("X-01")
        if x01:
            if not tools:
                findings.append(_unevaluated(x01, Outcome.skipped, "tools/list succeeded: no applicable tools"))
            else:
                findings.append(security_checks.check_dangerous_capabilities(tools, x01))

        # R-01 traversal & R-02 sensitive path
        r01 = spec_index.get("R-01")
        if r01:
            attempt = rpc("resources/read", {"uri": "file:///../../etc/hosts"})
            accepted = isinstance(attempt, dict) and "result" in attempt and isinstance(attempt.get("result"), dict)
            findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))
        r02 = spec_index.get("R-02")
        if r02:
            attempt2 = rpc("resources/read", {"uri": "file:///etc/passwd"})
            accepted2 = isinstance(attempt2, dict) and "result" in attempt2 and isinstance(attempt2.get("result"), dict)
            findings.append(_finding(r02, passed=not accepted2, details=json.dumps(attempt2)))

        # X-02 fuzz tools/call
        x02 = spec_index.get("X-02")
        if x02 and isinstance(tools, list):
            if len(tools) == 0:
                findings.append(_unevaluated(x02, Outcome.skipped, "tools/list succeeded: no applicable tools"))
            else:
                payloads = ["; id", "$(whoami)", "`uname - a`", "../../../../etc/passwd", "http://169.254.169.254/latest/meta-data/"]
                observed: List[Dict[str, Any]] = []
                for t in tools:
                    name = t.get("name")
                    schema = t.get("inputSchema") or {}
                    props = schema.get("properties") or {}
                    str_param = None
                    for pn, p in (props.items() if isinstance(props, dict) else []):
                        if (p.get("type") == "string"):
                            str_param = pn
                            break
                    if not (name and str_param):
                        continue
                    for pl in payloads:
                        resp = rpc("tools/call", {"name": name, "arguments": {str_param: pl}})
                        text = json.dumps(resp).lower()
                        if any(key in text for key in ["uid=", "linux", "root:x:", "etc/passwd", "meta-data", "insecure", "stdout"]):
                            observed.append({"tool": name, "payload": pl, "resp": resp})
                            break
                findings.append(_finding(x02, passed=len(observed) == 0, details=json.dumps(observed)))

        # Resources listing
        resources = enumerate_items("resources", ("R-03", "R-04", "R-05", "P-03"))

        # R-03 sensitive exposure
        r03 = spec_index.get("R-03")
        if r03:
            sensitive_keywords = ["credential", "secret", "token", "key", "password"]
            suspects: List[Dict[str, Any]] = []
            for r in resources or []:
                name = (r.get("name") or "").lower()
                uri = (r.get("uri") or "").lower()
                if any(k in name or k in uri for k in sensitive_keywords):
                    if r.get("uri"):
                        resp = rpc("resources/read", {"uri": r["uri"]})
                        text = json.dumps(resp).lower()
                        if any(x in text for x in ["password", "apikey", "api key", "sk-", "postgresql://", "username:"]):
                            suspects.append({"resource": r, "resp": resp})
                    else:
                        suspects.append({"resource": r, "resp": None})
            findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)) if resources else _unevaluated(r03, Outcome.skipped, "resources/list succeeded: no applicable resources"))

        # R-05 private
        r05 = spec_index.get("R-05")
        if r05:
            leaks: List[Dict[str, Any]] = []
            for r in resources or []:
                uri = r.get("uri")
                if isinstance(uri, str) and uri.startswith("private://"):
                    resp = rpc("resources/read", {"uri": uri})
                    text = json.dumps(resp).lower()
                    if any(x in text for x in ["secret", "token", "password"]):
                        leaks.append({"resource": r, "resp": resp})
            findings.append(_finding(r05, passed=len(leaks) == 0, details=json.dumps(leaks)) if resources else _unevaluated(r05, Outcome.skipped, "resources/list succeeded: no applicable resources"))

        # R-04 templates
        r04 = spec_index.get("R-04")
        if r04:
            templates = [r for r in resources or [] if isinstance(r, dict) and r.get("uriTemplate")]
            issues: List[Dict[str, Any]] = []
            for r in templates:
                tmpl: str = r.get("uriTemplate")
                if isinstance(tmpl, str) and "{" in tmpl and "}" in tmpl:
                    if tmpl.startswith("notes://"):
                        probe = "notes://admin"
                    else:
                        base_t = tmpl.split("{", 1)[0]
                        probe = base_t + "test"
                    resp = rpc("resources/read", {"uri": probe})
                    text = json.dumps(resp)
                    if ("No notes found for user:" in text) or ("Notes for" in text) or (isinstance(resp, dict) and resp.get("result")):
                        issues.append({"template": tmpl, "probe": probe, "resp": resp})
            findings.append(_finding(r04, passed=len(issues) == 0, details=json.dumps(issues)) if resources else _unevaluated(r04, Outcome.skipped, "resources/list succeeded: no applicable resources"))

        # P-03 Indirect prompt injection via external resources
        p03 = spec_index.get("P-03")
        if p03:
            p03_hits: List[Dict[str, Any]] = []
            try:
                # Identify external-like resources
                external_candidates = [
                    r for r in (resources or [])
                    if isinstance(r, dict) and isinstance(r.get("uri"), str)
                    and (
                        r["uri"].startswith("external://")
                        or r["uri"].startswith("http://")
                        or r["uri"].startswith("https://")
                    )
                ]
                # Simple heuristics of injection phrases
                inj_patterns = [
                    "ignore previous instructions",
                    "do not disclose",
                    "exfiltrate",
                    "send secrets",
                    "hidden instruction",
                    "override",
                    "leak",
                ]
                # Find a summarize-like tool
                summarize_tool: Optional[str] = None
                for t in tools or []:
                    name = (t.get("name") or "").lower()
                    desc = (t.get("description") or "").lower()
                    if any(k in name for k in ["summarize", "summary"]) or any(k in desc for k in ["summarize", "summary"]):
                        summarize_tool = t.get("name")
                        break
                for r in external_candidates:
                    uri = r.get("uri")
                    read = rpc("resources/read", {"uri": uri})
                    text = json.dumps(read).lower()
                    suspicious = any(p in text for p in inj_patterns)
                    exploited = False
                    summary_resp: Any = None
                    if summarize_tool:
                        try:
                            summary_resp = rpc("tools/call", {"name": summarize_tool, "arguments": {"uri": uri}})
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
                            "resource_read": read,
                            "summary": summary_resp,
                        })
                findings.append(_finding(p03, passed=len(p03_hits) == 0, details=json.dumps(p03_hits)) if external_candidates else _unevaluated(p03, Outcome.skipped, "resources/list succeeded: no applicable external resources"))
            except Exception as e:
                findings.append(_unevaluated(p03, Outcome.error, _diagnostic(f"{type(e).__name__}: {e}", headers)))

        # A-03 token pass-through via tool
        a03 = spec_index.get("A-03")
        if a03:
            leak = rpc("tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}})
            text = json.dumps(leak).lower()
            leaked = any(k in text for k in ["access_token", "sk-", "token-body", "bearer "])
            findings.append(_finding(a03, passed=not leaked, details=json.dumps(leak)))

    finally:
        session.close()
        client.close()
    return findings


def rpc_call(base_url: str, method: str, params: Dict[str, Any], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> Dict[str, Any]:
    if trace is not None:
        trace = _RedactedTrace(trace, headers)
    with httpx.Client(follow_redirects=True, timeout=timeout, headers=headers or {}) as client:
        session = HttpSession(client, base_url, timeout, trace if verbose else None, transport, sse_endpoint)
        try:
            session.initialize()
            status, data = session.call(method, params)
            return data if isinstance(data, dict) else {"status": status, "body": data}
        except Exception as exc:
            return {"error": _diagnostic(f"{type(exc).__name__}: {exc}", headers)}
        finally:
            session.close()


def get_server_health(base_url: str, headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> Dict[str, Any]:
    """Return verified initialization and enumeration outcomes for debugging.

    Unavailable lists are None; successfully retrieved empty lists are [].
    Legacy endpoint discovery alone is not accepted as initialization.
    """
    if trace is not None:
        trace = _RedactedTrace(trace, headers)
    init_status: Optional[int] = None
    init_error: Optional[str] = None
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )
    _set_mcp_http_headers(client)
    session = HttpSession(client, base_url, timeout, trace if verbose else None, transport, sse_endpoint)

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        # Endpoint ownership belongs to the initialized session. The internal
        # ID is normalized only after the unique wire ID has been correlated.
        if payload.get("id") == 99:
            status, data = session.call(payload["method"], payload.get("params", {}))
            if isinstance(data, dict) and "id" in data:
                data = {**data, "id": 99}
            return status, data
        return session.exchange(payload)

    def _discover_endpoint() -> Tuple[Optional[str], Dict[str, Any]]:
        nonlocal init_status, init_error
        try:
            init_status, data = session.initialize()
            return session.url, data
        except Exception as exc:
            init_status = session.initialize_status
            init_error = f"HTTP {init_status}; {type(exc).__name__}: {exc}"
            return None, {}

    try:
        health: Dict[str, Any] = {
            "base_url": _diagnostic(base_url, headers), "msg_url": None, "sse_url": None,
            "status": "error", "initialize": None, "initialize_http_status": None,
            "tools": None, "prompts": None, "resources": None,
            "enumeration_status": {key: "skipped" for key in ("tools", "prompts", "resources")},
            "errors": {},
        }
        init_url, init_obj = _discover_endpoint()
        health["initialize_http_status"] = init_status
        health["transport"] = session.transport
        health["sse_url"] = _diagnostic(session.sse_url, headers) if session.transport == "sse" else None
        problem = init_error or _initialization_problem(init_status, init_obj)
        if problem or init_url is None:
            health["errors"]["initialize"] = _diagnostic(problem or "No endpoint discovered", headers)
            return health
        health.update(msg_url=_diagnostic(init_url, headers), initialize=init_obj, status="ok")
        for key in ("tools", "prompts", "resources"):
            method = key + "/list"
            try:
                status, data = _post_json(init_url, {
                    "jsonrpc": "2.0", "id": 99, "method": method, "params": {},
                })
                problem = _enumeration_problem(status, data, key)
            except Exception as exc:
                problem = f"{type(exc).__name__}: {exc}"
            if problem:
                health["status"] = "error"
                health["enumeration_status"][key] = "error"
                health["errors"][method] = _diagnostic(problem, headers)
            else:
                health["enumeration_status"][key] = "ok"
                health[key] = data["result"][key]
        return health
    finally:
        session.close()
        client.close()
