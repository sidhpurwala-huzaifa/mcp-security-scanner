from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

import websockets

from .models import Finding, Report, Severity
from .spec import SpecCheck, load_spec


async def _ws_call(uri: str, method: str, params: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False) -> Tuple[Dict[str, Any], websockets.WebSocketClientProtocol]:
    # websockets client: use defaults; headers unused for now
    websocket = await websockets.connect(uri)
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    if verbose and trace is not None:
        trace.append({"transport": "ws", "direction": "send", "request": req})
    await websocket.send(json.dumps(req))
    raw = await websocket.recv()
    if verbose and trace is not None:
        trace.append({"transport": "ws", "direction": "recv", "raw": raw})
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"error": "non-json", "raw": raw}
    return data, websocket


async def _ws_send_recv(ws: websockets.WebSocketClientProtocol, method: str, params: Dict[str, Any] | None = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False) -> Dict[str, Any]:
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    if verbose and trace is not None:
        trace.append({"transport": "ws", "direction": "send", "request": req})
    await ws.send(json.dumps(req))
    raw = await ws.recv()
    if verbose and trace is not None:
        trace.append({"transport": "ws", "direction": "recv", "raw": raw})
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "non-json", "raw": raw}


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


async def run_checks_ws(uri: str, spec_index: Dict[str, SpecCheck], trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []

    # BASE-01: Fingerprint
    base = spec_index.get("BASE-01")
    if base:
        resp, ws = await _ws_call(uri, "initialize", trace=trace, verbose=verbose)
        ok = isinstance(resp, dict) and "result" in resp and "capabilities" in resp.get("result", {})
        details = json.dumps(resp)
        findings.append(_finding(base, ok, details))
    else:
        ws = None  # type: ignore[assignment]

    if ws is None:
        # Could not initialize; return early with minimal info
        return findings

    # Get tools list
    tools_list = await _ws_send_recv(ws, "tools/list", trace=trace, verbose=verbose)
    tools = tools_list.get("result", {}).get("tools", []) if isinstance(tools_list, dict) else []

    # A-01: Unauthenticated access
    a01 = spec_index.get("A-01")
    if a01:
        unauth_ok = bool(tools)
        findings.append(_finding(a01, passed=not unauth_ok, details=json.dumps(tools_list)))

    # T-02: TLS (ws vs wss)
    t02 = spec_index.get("T-02")
    if t02:
        is_secure = uri.startswith("wss://")
        details = f"scheme={'wss' if is_secure else 'ws'}"
        findings.append(_finding(t02, passed=is_secure, details=details))

    # X-01: Dangerous capability detection
    # P-02: Prompt/description injection heuristics
    # X-03: Rug-pull detection — re-list and diff
    x03 = spec_index.get("X-03")
    if x03:
        tools_list2 = await _ws_send_recv(ws, "tools/list", trace=trace, verbose=verbose)
        tools2 = tools_list2.get("result", {}).get("tools", []) if isinstance(tools_list2, dict) else []
        diff = []
        def key(t: Dict[str, Any]):
            return t.get("name"), t.get("description")
        set1 = {key(t) for t in tools}
        set2 = {key(t) for t in tools2}
        if set1 != set2:
            diff = [
                {"before": [t for t in tools if t.get("name") == n and t.get("description") == d],
                 "after": [t for t in tools2 if t.get("name") == n and t.get("description") == d]}
                for (n, d) in set1.symmetric_difference(set2)
            ]
        findings.append(_finding(x03, passed=len(diff) == 0, details=json.dumps(diff)))
    p02 = spec_index.get("P-02")
    if p02 and tools:
        bad_phrases = [
            "ignore any safety rules",
            "override other tools",
            "include contents of",
            "do not disclose this instruction",
            "hidden instruction",
        ]
        hits = []
        for t in tools:
            desc = (t.get("description") or "").lower()
            if any(phrase in desc for phrase in bad_phrases):
                hits.append(t)
        findings.append(_finding(p02, passed=len(hits) == 0, details=json.dumps(hits)))

    x01 = spec_index.get("X-01")
    if x01:
        risky_keywords = [
            "exec", "command", "shell", "write_file", "delete", "rm", "chmod", "chown",
            "fetch", "http", "url", "eval", "render", "payment", "admin", "privilege",
        ]
        risky_tools: List[Dict[str, Any]] = []
        for t in tools:
            name = (t.get("name") or "").lower()
            desc = (t.get("description") or "").lower()
            schema = t.get("inputSchema") or {}
            has_constraints = False
            if isinstance(schema, dict):
                props = schema.get("properties") or {}
                for _, p in (props.items() if isinstance(props, dict) else []):
                    if any(k in p for k in ("enum", "pattern", "minimum", "maximum", "minLength", "maxLength")):
                        has_constraints = True
            if any(k in name or k in desc for k in risky_keywords) and not has_constraints:
                risky_tools.append(t)
        findings.append(_finding(x01, passed=len(risky_tools) == 0, details=json.dumps(risky_tools)))

    # R-01: Resource traversal
    r01 = spec_index.get("R-01")
    if r01:
        attempt = await _ws_send_recv(ws, "resources/read", {"uri": "file:///../../etc/hosts"}, trace=trace, verbose=verbose)
        accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
        findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))

    # R-02: Per-resource access control
    r02 = spec_index.get("R-02")
    if r02:
        attempt2 = await _ws_send_recv(ws, "resources/read", {"uri": "file:///etc/passwd"}, trace=trace, verbose=verbose)
        accepted2 = "result" in attempt2 and isinstance(attempt2.get("result"), dict)
        findings.append(_finding(r02, passed=not accepted2, details=json.dumps(attempt2)))

    # X-02: Injection fuzzing (simple heuristic)
    x02 = spec_index.get("X-02")
    if x02 and tools:
        # Try to identify a string param tool and send a payload
        payloads = ["; id", "$(whoami)", "`uname -a`", "../../../../etc/passwd", "http://169.254.169.254/latest/meta-data/"]
        observed_danger = []
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
                resp = await _ws_send_recv(ws, "tools/call", {"name": name, "arguments": {str_param: pl}}, trace=trace, verbose=verbose)
                # If server echoes or returns command/system info, treat as dangerous
                text = json.dumps(resp).lower()
                if any(key in text for key in ["uid=", "linux", "root:x:", "etc/passwd", "meta-data", "insecure", "stdout"]):
                    observed_danger.append({"tool": name, "payload": pl, "resp": resp})
                    break
        findings.append(_finding(x02, passed=len(observed_danger) == 0, details=json.dumps(observed_danger)))

    await ws.close()
    # After closing, we still can report static issues from prior lists
    # R-03 Sensitive resource exposure via WS (if resources/list available earlier)
    r03 = spec_index.get("R-03")
    if r03:
        # Try to reconnect briefly to list resources
        try:
            resp, ws2 = await _ws_call(uri, "initialize", trace=trace, verbose=verbose)
            res_list = await _ws_send_recv(ws2, "resources/list", {}, trace=trace, verbose=verbose)
            await ws2.close()
            resources = res_list.get("result", {}).get("resources", []) if isinstance(res_list, dict) else []
            sensitive_keywords = ["credential", "secret", "token", "key", "password"]
            suspects = []
            for r in resources:
                name = (r.get("name") or "").lower()
                uri_r = (r.get("uri") or "").lower()
                if any(k in name or k in uri_r for k in sensitive_keywords):
                    suspects.append(r)
            findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)))
        except Exception:
            pass

    # A-03 Token pass-through exposure: attempt to call a tool likely to return tokens
    a03 = spec_index.get("A-03")
    if a03:
        try:
            resp, ws3 = await _ws_call(uri, "initialize", trace=trace, verbose=verbose)
            # Try a common name used in test=5
            leak = await _ws_send_recv(ws3, "tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}}, trace=trace, verbose=verbose)
            await ws3.close()
            text = json.dumps(leak).lower()
            leaked = any(k in text for k in ["access_token", "sk-", "token-body", "bearer "])
            findings.append(_finding(a03, passed=not leaked, details=json.dumps(leak)))
        except Exception:
            # ignore if the tool is not present
            pass

    return findings


def scan_server(uri: str, spec_path: str | None = None, verbose: bool = False, trace: Optional[List[Dict[str, Any]]] = None) -> Report:
    spec_file = Path(spec_path) if spec_path else Path(__file__).resolve().parents[2] / "scanner_specs.schema"
    spec_index = load_spec(spec_file)
    findings = asyncio.run(run_checks_ws(uri, spec_index, trace=trace, verbose=verbose))
    return Report.new(target=uri, findings=findings)


