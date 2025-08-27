from __future__ import annotations

from typing import Dict, List, Optional, Any
import json

import httpx

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


def scan_http_base(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    client = httpx.Client(follow_redirects=True, timeout=5.0, headers=headers or {})

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
            # Probe SSE endpoint existence first
            sse_url = base_url.rstrip("/") + "/sse"
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url})
            r_ok = client.get(sse_url)
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": r_ok.status_code, "headers": dict(r_ok.headers)})
            exists = r_ok.status_code < 500
            # Now try forged Origin
            forged_headers = {**({} if headers is None else headers), "Origin": "http://evil.tld"}
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "headers": {"Origin": "http://evil.tld"}})
            r = client.get(sse_url, headers=forged_headers)
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "headers": dict(r.headers)})
            accepts_cross = r.status_code < 400
            passed = exists and not accepts_cross
            details = f"sse={r_ok.status_code}; forged_origin={r.status_code}"
        except Exception as e:  # noqa: BLE001
            passed = False
            details = f"error={type(e).__name__}:{e}"
        findings.append(_finding(t01, passed=passed, details=details))

    # KF-03 Unsafe bind address: best-effort heuristic — if reachable on 0.0.0.0 it's exposed
    kf03 = spec_index.get("KF-03")
    if kf03:
        # If server is reachable via localhost and responds, assume it's listening on all interfaces
        # This is a heuristic and will mark as fail to encourage loopback-only binding in local setups.
        try:
            sse_url = base_url.rstrip("/") + "/sse"
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url})
            r = client.get(sse_url)
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": r.status_code})
            reachable = r.status_code < 500
            findings.append(_finding(kf03, passed=not reachable, details=f"status={r.status_code}"))
        except Exception as e:  # noqa: BLE001
            findings.append(_finding(kf03, passed=True, details=f"error={type(e).__name__}:{e}"))

    client.close()
    return findings


def run_full_http_checks(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    client = httpx.Client(follow_redirects=True, timeout=6.0, headers=headers or {})
    try:
        # T-02 already implied by schema; reuse scan_http_base for T-01/T-02/KF-03
        findings.extend(scan_http_base(base_url, spec_index, headers=headers, trace=trace, verbose=verbose))

        # A-01: Unauthenticated access (probe without Authorization)
        a01 = spec_index.get("A-01")
        if a01:
            try:
                unauth = httpx.Client(follow_redirects=True, timeout=6.0)
                payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                # Try minimal default candidates; capabilities refine later
                candidates = [
                    base_url.rstrip("/") + "/messages",
                    base_url.rstrip("/") + "/messages/",
                ]
                status = None
                body_text = ""
                for msg_url in candidates:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": payload, "url": msg_url})
                    r = unauth.post(msg_url, json=payload)
                    status = r.status_code
                    try:
                        body_text = r.text
                    except Exception:
                        body_text = ""
                    if verbose and trace is not None:
                        try:
                            body = r.json()
                        except Exception:
                            body = r.text
                        trace.append({"transport": "http", "direction": "recv", "status": status, "data": body})
                    # Accept first non-404 as authoritative
                    if status != 404:
                        break
                is_denied = (status in (401, 403)) if status is not None else False
                details = f"status={status}, body={(body_text[:200] + '...') if len(body_text)>200 else body_text}"
                findings.append(_finding(a01, passed=is_denied, details=details))
            except Exception as e:
                findings.append(_finding(a01, passed=False, details=f"error={type(e).__name__}:{e}"))

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
                findings.append(_finding(a02, passed=False, details=f"error={type(e).__name__}:{e}"))

        # T-03: Session identifier handling (best-effort)
        t03 = spec_index.get("T-03")
        if t03:
            try:
                init_payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
                candidates = [
                    base_url.rstrip("/") + "/messages",
                    base_url.rstrip("/") + "/messages/",
                ]
                sess = None
                last_status = None
                chosen_url = None
                init_json: Optional[Dict[str, Any]] = None
                for msg_url in candidates:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": init_payload, "url": msg_url})
                    init = client.post(msg_url, json=init_payload)
                    last_status = init.status_code
                    sess = init.headers.get("Mcp-Session-Id") or init.cookies.get("mcp_session")
                    try:
                        init_json = init.json()
                    except Exception:
                        init_json = None
                    if sess or (last_status and last_status != 404) or (init_json and isinstance(init_json, dict) and init_json.get("result")):
                        chosen_url = msg_url
                        break
                ok = bool(sess)
                # Try an altered session id if we have a chosen URL
                if chosen_url and sess:
                    bad_headers = dict(client.headers)
                    if "Mcp-Session-Id" not in bad_headers:
                        bad_headers["Mcp-Session-Id"] = sess + "-x"
                    bad_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": bad_payload, "url": chosen_url, "note": "altered session id"})
                    bad = httpx.post(chosen_url, json=bad_payload, headers=bad_headers, timeout=6.0)
                    rejects_bad = bad.status_code in (401, 403, 400)
                    if verbose and trace is not None:
                        try:
                            bad_body = bad.json()
                        except Exception:
                            bad_body = bad.text
                        trace.append({"transport": "http", "direction": "recv", "status": bad.status_code, "data": bad_body})
                else:
                    rejects_bad = False
                findings.append(_finding(t03, passed=(ok and rejects_bad), details=f"session_present={bool(sess)}, status={last_status}"))
                # Expose chosen URL and init_json to capability extraction below via closures
                discovered_url = chosen_url
                discovered_init = init_json
            except Exception as e:
                discovered_url = None
                discovered_init = None
                findings.append(_finding(t03, passed=False, details=f"error={type(e).__name__}:{e}"))

        # JSON-RPC helper over messages with endpoint discovery
        msg_url_cache: Optional[str] = None
        if 'discovered_url' in locals() and discovered_url:
            msg_url_cache = discovered_url

        def rpc(method: str, params: Dict[str, object]) -> Dict[str, object]:
            nonlocal msg_url_cache
            candidates = [
                base_url.rstrip("/") + "/messages",
                base_url.rstrip("/") + "/messages/",
            ]
            if msg_url_cache:
                candidates = [msg_url_cache]
            last_error: Optional[Dict[str, Any]] = None
            payload = {"jsonrpc": "2.0", "id": 99, "method": method, "params": params}
            for msg_url in candidates:
                try:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": payload, "url": msg_url})
                    r = client.post(msg_url, json=payload)
                    try:
                        data = r.json()
                        if verbose and trace is not None:
                            trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "data": data})
                        if isinstance(data, dict):
                            msg_url_cache = msg_url
                        return data
                    except Exception:
                        if verbose and trace is not None:
                            trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "raw": r.text})
                        last_error = {"status": r.status_code, "body": r.text}
                        # try next candidate
                except Exception as e:
                    last_error = {"error": f"{type(e).__name__}:{e}"}
                    continue
            return last_error or {"error": "no-endpoint"}

        # BASE-01: initialize
        base = spec_index.get("BASE-01")
        init = {}
        if base:
            init = rpc("initialize", {"capabilities": {}, "clientInfo": {"name": "mcp-security-scanner", "version": "0.1.0"}})
            ok = isinstance(init, dict) and "result" in init and "capabilities" in init.get("result", {})
            findings.append(_finding(base, ok, json.dumps(init)))

        # If initialize returned capability paths, try to refine msg_url_cache
        try:
            caps = (init.get("result", {}) if isinstance(init, dict) else {}).get("capabilities", {})
            paths: List[str] = []
            def _collect_paths(obj: Any) -> None:
                if isinstance(obj, dict):
                    for v in obj.values():
                        _collect_paths(v)
                elif isinstance(obj, list):
                    for v in obj:
                        _collect_paths(v)
                elif isinstance(obj, str) and obj.startswith("/"):
                    paths.append(obj)
            _collect_paths(caps)
            for p in paths:
                base_p = base_url.rstrip("/") + p
                probe_candidates = [
                    base_p,
                    base_p.rstrip("/") + "/message",
                    base_p.rstrip("/") + "/list",
                ]
                for u in probe_candidates:
                    payload = {"jsonrpc": "2.0", "id": 42, "method": "tools/list", "params": {}}
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": payload, "url": u, "note": "capability path probe"})
                    resp = client.post(u, json=payload)
                    if resp.status_code != 404:
                        try:
                            _ = resp.json()
                            msg_url_cache = u
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "recv", "status": resp.status_code, "note": "selected capability path"})
                            raise StopIteration  # break both loops
                        except Exception:
                            continue
        except StopIteration:
            pass
        except Exception:
            pass

        # tools/list
        tools_list: Dict[str, Any] = rpc("tools/list", {})
        tools = tools_list.get("result", {}).get("tools", []) if isinstance(tools_list, dict) else []

        # X-03: Rug-pull diff tools
        x03 = spec_index.get("X-03")
        if x03:
            tools_list2 = rpc("tools/list", {})
            tools2 = tools_list2.get("result", {}).get("tools", []) if isinstance(tools_list2, dict) else []
            def key(t: Dict[str, Any]):
                return t.get("name"), t.get("description")
            set1 = {key(t) for t in tools or []}
            set2 = {key(t) for t in tools2 or []}
            diff = []
            if set1 != set2:
                diff = [
                    {"before": [t for t in tools if t.get("name") == n and t.get("description") == d],
                    "after": [t for t in tools2 if t.get("name") == n and t.get("description") == d]}
                    for (n, d) in set1.symmetric_difference(set2)
                ]
            findings.append(_finding(x03, passed=len(diff) == 0, details=json.dumps(diff)))

        # P-02: Prompt/description injection heuristics over HTTP
        p02 = spec_index.get("P-02")
        if p02 and isinstance(tools, list):
            bad_phrases = [
                "ignore any safety rules",
                "override other tools",
                "include contents of",
                "do not disclose this instruction",
                "hidden instruction",
            ]
            hits: List[Dict[str, object]] = []
            for t in tools:
                desc = (t.get("description") or "").lower()
                if any(phrase in desc for phrase in bad_phrases):
                    hits.append(t)
            findings.append(_finding(p02, passed=len(hits) == 0, details=json.dumps(hits)))

        # P-01: Prompt argument validation (best-effort)
        p01 = spec_index.get("P-01")
        if p01:
            try:
                plist = rpc("prompts/list", {})
                prompts = plist.get("result", {}).get("prompts", []) if isinstance(plist, dict) else []
                ok = True
                details = []
                for pr in prompts or []:
                    name = pr.get("name")
                    # Call prompts/get with missing args
                    resp = rpc("prompts/get", {"name": name})
                    if "result" in resp and not resp.get("error"):
                        ok = False
                        details.append({"prompt": name, "resp": resp})
                findings.append(_finding(p01, passed=ok, details=json.dumps(details)))
            except Exception as e:
                findings.append(_finding(p01, passed=False, details=f"error={type(e).__name__}:{e}"))

        # P-03: Indirect prompt injection via external resources
        p03 = spec_index.get("P-03")
        if p03:
            inj_hits: List[Dict[str, object]] = []
            try:
                rlist = rpc("resources/list", {})
                resources = rlist.get("result", {}).get("resources", []) if isinstance(rlist, dict) else []
                phrases = ["hidden instruction", "ignore previous safety rules", "do not disclose this instruction", "exfiltrate"]
                for rsc in resources or []:
                    uri = rsc.get("uri")
                    if isinstance(uri, str) and uri.startswith("external://"):
                        rread = rpc("resources/read", {"uri": uri})
                        text = json.dumps(rread).lower()
                        if any(p in text for p in phrases):
                            inj_hits.append({"resource": rsc, "resp": rread})
                        # Try summarize_resource if present
                        if any(t.get("name") == "summarize_resource" for t in tools or []):
                            sresp = rpc("tools/call", {"name": "summarize_resource", "arguments": {"uri": uri}})
                            stext = json.dumps(sresp).lower()
                            if any(p in stext for p in phrases):
                                inj_hits.append({"resource": rsc, "summary": sresp})
                findings.append(_finding(p03, passed=len(inj_hits) == 0, details=json.dumps(inj_hits)))
            except Exception as e:
                findings.append(_finding(p03, passed=False, details=f"error={type(e).__name__}:{e}"))

        # X-01: Risky unconstrained tools
        x01 = spec_index.get("X-01")
        if x01:
            risky_keywords = [
                "exec", "command", "shell", "write_file", "delete", "rm", "chmod", "chown",
                "fetch", "http", "url", "eval", "render", "payment", "admin", "privilege",
            ]
            risky_tools: List[Dict[str, Any]] = []
            for t in tools or []:
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

        # R-01: Resource traversal prevention
        r01 = spec_index.get("R-01")
        if r01:
            attempt = rpc("resources/read", {"uri": "file:///../../etc/hosts"})
            accepted = isinstance(attempt, dict) and "result" in attempt and isinstance(attempt.get("result"), dict)
            findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))

        # R-02: Per-resource access control for sensitive paths
        r02 = spec_index.get("R-02")
        if r02:
            attempt2 = rpc("resources/read", {"uri": "file:///etc/passwd"})
            accepted2 = isinstance(attempt2, dict) and "result" in attempt2 and isinstance(attempt2.get("result"), dict)
            findings.append(_finding(r02, passed=not accepted2, details=json.dumps(attempt2)))

        # X-02: Injection fuzzing on string params
        x02 = spec_index.get("X-02")
        if x02 and isinstance(tools, list):
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

        # Resources list to support R-03/R-04/R-05
        rlist = rpc("resources/list", {})
        resources = rlist.get("result", {}).get("resources", []) if isinstance(rlist, dict) else []

        # R-03: Sensitive resource exposure
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
            findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)))

        # R-05: Private resource exposure
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
            findings.append(_finding(r05, passed=len(leaks) == 0, details=json.dumps(leaks)))

        # R-04: User-controlled resource templates without validation
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
                    if ("No notes found for user:" in text) or ("Notes for" in text) or resp.get("result"):
                        issues.append({"template": tmpl, "probe": probe, "resp": resp})
            findings.append(_finding(r04, passed=len(issues) == 0, details=json.dumps(issues)))

        # A-03: Token pass-through / leak by tool
        a03 = spec_index.get("A-03")
        if a03:
            leak = rpc("tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}})
            text = json.dumps(leak).lower()
            leaked = any(k in text for k in ["access_token", "sk-", "token-body", "bearer "])
            findings.append(_finding(a03, passed=not leaked, details=json.dumps(leak)))
    finally:
        client.close()
    return findings


