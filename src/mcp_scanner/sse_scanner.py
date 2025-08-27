from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx
from httpx_sse import connect_sse

from .models import Finding, Severity
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


def sse_send_receive(base_url: str, payload: Dict[str, Any], trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    sse_url = base_url.rstrip("/") + "/sse"
    with httpx.Client(timeout=5.0, follow_redirects=True, headers=headers or {}) as client:
        with connect_sse(client, method="GET", url=sse_url) as event_source:
            events = event_source.iter_sse()
            post_path = None
            for ev in events:
                if getattr(ev, "event", None) == "endpoint":
                    post_path = ev.data
                    break
            if not post_path:
                return {"error": "no-endpoint", "raw": None}
            if not post_path.startswith("/"):
                post_path = "/" + post_path
            post_url = base_url.rstrip("/") + post_path
            if verbose and trace is not None:
                trace.append({"transport": "sse", "direction": "send", "request": payload, "post_url": post_url})
            req_headers = {"content-type": "application/json"}
            if headers:
                req_headers.update(headers)
            resp = client.post(post_url, content=json.dumps(payload), headers=req_headers)
            resp.raise_for_status()
            for ev in events:
                if getattr(ev, "event", None) == "message":
                    try:
                        data = json.loads(ev.data)
                        if verbose and trace is not None:
                            trace.append({"transport": "sse", "direction": "recv", "data": data})
                        return data
                    except json.JSONDecodeError:
                        if verbose and trace is not None:
                            trace.append({"transport": "sse", "direction": "recv", "raw": ev.data})
                        return {"error": "non-json", "raw": ev.data}
            return {"error": "no-message"}


def run_checks_sse(base_url: str, spec_index: Dict[str, SpecCheck], trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, auth_headers: Optional[Dict[str, str]] = None) -> List[Finding]:
    findings: List[Finding] = []

    # BASE-01 initialize
    base = spec_index.get("BASE-01")
    if base:
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}, "clientInfo": {"name": "mcp-security-scanner", "version": "0.1.0"}},
        }
        resp = sse_send_receive(base_url, init, trace=trace, verbose=verbose, headers=auth_headers)
        ok = isinstance(resp, dict) and "result" in resp and "capabilities" in resp.get("result", {})
        findings.append(_finding(base, ok, json.dumps(resp)))

    # tools/list
    tools = []
    # If auth provided, probe unauth first to evaluate A-01
    a01 = spec_index.get("A-01")
    pre_tools_list = None
    if auth_headers:
        pre_tools_list = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, trace=trace, verbose=verbose, headers=None)
    tools_list = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, trace=trace, verbose=verbose, headers=auth_headers)
    if isinstance(tools_list, dict):
        tools = tools_list.get("result", {}).get("tools", [])

    # A-01: if tools are accessible without auth
    if a01:
        if auth_headers:
            unauth_tools = pre_tools_list.get("result", {}).get("tools", []) if isinstance(pre_tools_list, dict) else []
            findings.append(_finding(a01, passed=(not bool(unauth_tools)), details=json.dumps(pre_tools_list)))
        else:
            findings.append(_finding(a01, passed=(not bool(tools)), details=json.dumps(tools_list)))

    # X-03: Rug-pull detection — re-list and diff
    x03 = spec_index.get("X-03")
    if x03:
        tools_list2 = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}}, trace=trace, verbose=verbose, headers=auth_headers)
        tools2 = tools_list2.get("result", {}).get("tools", []) if isinstance(tools_list2, dict) else []
        diff = []
        def key(t):
            return t.get("name"), t.get("description")
        set1 = {key(t) for t in tools}
        set2 = {key(t) for t in tools2}
        if set1 != set2:
            # capture differences
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
        hits: List[Dict[str, Any]] = []
        for t in tools:
            desc = (t.get("description") or "").lower()
            if any(phrase in desc for phrase in bad_phrases):
                hits.append(t)
        findings.append(_finding(p02, passed=len(hits) == 0, details=json.dumps(hits)))

    # X-01 risky tools unconstrained
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

    # R-01 traversal attempt via resources/read
    r01 = spec_index.get("R-01")
    if r01:
        attempt = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///../../etc/hosts"}}, trace=trace, verbose=verbose, headers=auth_headers)
        accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
        findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))

    # Resources listing and sensitive exposure (R-03) and templates (R-04)
    res_list = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 10, "method": "resources/list", "params": {}}, trace=trace, verbose=verbose, headers=auth_headers)
    resources = res_list.get("result", {}).get("resources", []) if isinstance(res_list, dict) else []

    # R-03 Sensitive resource exposure
    r03 = spec_index.get("R-03")
    if r03:
        sensitive_keywords = ["credential", "secret", "token", "key", "password"]
        suspects = []
        for r in resources:
            name = (r.get("name") or "").lower()
            uri = (r.get("uri") or "").lower()
            if any(k in name or k in uri for k in sensitive_keywords):
                # try read if uri present
                if r.get("uri"):
                    resp = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 11, "method": "resources/read", "params": {"uri": r["uri"]}}, trace=trace, verbose=verbose, headers=auth_headers)
                    text = json.dumps(resp).lower()
                    if any(x in text for x in ["password", "apikey", "api key", "sk-", "postgresql://", "username:"]):
                        suspects.append({"resource": r, "resp": resp})
                else:
                    suspects.append({"resource": r, "resp": None})
        findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)))

    # R-05 Private resource exposure
    r05 = spec_index.get("R-05")
    if r05:
        leaks = []
        for r in resources:
            uri = r.get("uri")
            if isinstance(uri, str) and uri.startswith("private://"):
                resp = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 13, "method": "resources/read", "params": {"uri": uri}}, trace=trace, verbose=verbose, headers=auth_headers)
                text = json.dumps(resp).lower()
                if any(x in text for x in ["secret", "token", "password"]):
                    leaks.append({"resource": r, "resp": resp})
        findings.append(_finding(r05, passed=len(leaks) == 0, details=json.dumps(leaks)))

    # P-03 Indirect prompt injection via external resources
    p03 = spec_index.get("P-03")
    if p03:
        inj_hits = []
        ext_resources = [r for r in resources if isinstance(r, dict) and isinstance(r.get("uri"), str) and r.get("uri").startswith("external://")]
        phrases = [
            "hidden instruction",
            "ignore previous safety rules",
            "do not disclose this instruction",
            "exfiltrate",
        ]
        for r in ext_resources:
            uri = r.get("uri")
            resp = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 14, "method": "resources/read", "params": {"uri": uri}}, trace=trace, verbose=verbose, headers=auth_headers)
            text = json.dumps(resp).lower()
            if any(p in text for p in phrases):
                inj_hits.append({"resource": r, "resp": resp})
            # If summarize_resource tool exists, call it
            if any(t.get("name") == "summarize_resource" for t in tools):
                sresp = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": {"name": "summarize_resource", "arguments": {"uri": uri}}}, trace=trace, verbose=verbose, headers=auth_headers)
                stext = json.dumps(sresp).lower()
                if any(p in stext for p in phrases):
                    inj_hits.append({"resource": r, "summary": sresp})
        findings.append(_finding(p03, passed=len(inj_hits) == 0, details=json.dumps(inj_hits)))

    # R-04 User-controlled templates without validation
    r04 = spec_index.get("R-04")
    if r04:
        templates = [r for r in resources if isinstance(r, dict) and r.get("uriTemplate")]
        issues = []
        for r in templates:
            tmpl: str = r.get("uriTemplate")
            if "{" in tmpl and "}" in tmpl:
                # try a crafted value, challenge1 expects notes://admin
                if tmpl.startswith("notes://"):
                    probe = "notes://admin"
                else:
                    # fallback: replace first {...} with 'test'
                    base = tmpl.split("{", 1)[0]
                    probe = base + "test"
                resp = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 12, "method": "resources/read", "params": {"uri": probe}}, trace=trace, verbose=verbose, headers=auth_headers)
                text = json.dumps(resp)
                if "No notes found for user:" in text or "Notes for" in text or resp.get("result"):
                    issues.append({"template": tmpl, "probe": probe, "resp": resp})
        findings.append(_finding(r04, passed=len(issues) == 0, details=json.dumps(issues)))

    # A-03 Token pass-through: call known leaking tool name
    a03 = spec_index.get("A-03")
    if a03:
        leak = sse_send_receive(base_url, {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {"name": "upstream_access", "arguments": {"code": "dummy"}}}, trace=trace, verbose=verbose, headers=auth_headers)
        text = json.dumps(leak).lower()
        leaked = any(k in text for k in ["access_token", "sk-", "token-body", "bearer "])
        findings.append(_finding(a03, passed=not leaked, details=json.dumps(leak)))

    return findings
