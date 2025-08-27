from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import websockets

from .models import Finding, Report, Severity
from .spec import SpecCheck, load_spec


async def _ws_call(uri: str, method: str, params: Dict[str, Any] | None = None, headers: Dict[str, str] | None = None) -> Tuple[Dict[str, Any], websockets.WebSocketClientProtocol]:
    # websockets client: use defaults; headers unused for now
    websocket = await websockets.connect(uri)
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    await websocket.send(json.dumps(req))
    raw = await websocket.recv()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"error": "non-json", "raw": raw}
    return data, websocket


async def _ws_send_recv(ws: websockets.WebSocketClientProtocol, method: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    await ws.send(json.dumps(req))
    raw = await ws.recv()
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


async def run_checks_ws(uri: str, spec_index: Dict[str, SpecCheck]) -> List[Finding]:
    findings: List[Finding] = []

    # BASE-01: Fingerprint
    base = spec_index.get("BASE-01")
    if base:
        resp, ws = await _ws_call(uri, "initialize")
        ok = isinstance(resp, dict) and "result" in resp and "capabilities" in resp.get("result", {})
        details = json.dumps(resp)
        findings.append(_finding(base, ok, details))
    else:
        ws = None  # type: ignore[assignment]

    if ws is None:
        # Could not initialize; return early with minimal info
        return findings

    # Get tools list
    tools_list = await _ws_send_recv(ws, "tools/list")
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
        attempt = await _ws_send_recv(ws, "resources/read", {"uri": "file:///../../etc/hosts"})
        accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
        findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))

    # R-02: Per-resource access control
    r02 = spec_index.get("R-02")
    if r02:
        attempt2 = await _ws_send_recv(ws, "resources/read", {"uri": "file:///etc/passwd"})
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
                resp = await _ws_send_recv(ws, "tools/call", {"name": name, "arguments": {str_param: pl}})
                # If server echoes or returns command/system info, treat as dangerous
                text = json.dumps(resp).lower()
                if any(key in text for key in ["uid=", "linux", "root:x:", "etc/passwd", "meta-data", "insecure", "stdout"]):
                    observed_danger.append({"tool": name, "payload": pl, "resp": resp})
                    break
        findings.append(_finding(x02, passed=len(observed_danger) == 0, details=json.dumps(observed_danger)))

    await ws.close()
    return findings


def scan_server(uri: str, spec_path: str | None = None) -> Report:
    spec_file = Path(spec_path) if spec_path else Path(__file__).resolve().parents[2] / "scanner_specs.schema"
    spec_index = load_spec(spec_file)
    findings = asyncio.run(run_checks_ws(uri, spec_index))
    return Report.new(target=uri, findings=findings)


