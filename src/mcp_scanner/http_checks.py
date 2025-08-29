from __future__ import annotations

from typing import Dict, List, Optional, Any, Tuple
import json

import httpx
from urllib.parse import urlparse, parse_qs

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

    # KF-03 Unsafe bind address (heuristic)
    kf03 = spec_index.get("KF-03")
    if kf03:
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


def run_full_http_checks(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto") -> List[Finding]:
    findings: List[Finding] = []
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )
    # Ensure required headers for Streamable HTTP compatibility
    if "Accept" not in client.headers:
        client.headers["Accept"] = "application/json, text/event-stream"
    client.headers.setdefault("MCP-Protocol-Version", "2025-06-18")

    # Cache discovered message URL and allow refresh from inner helpers
    msg_url_cache: Optional[str] = None

    def _parse_sse_response(resp: httpx.Response) -> Any:
        # Parse SSE and return the first JSON-RPC response object encountered
        buffer: List[str] = []
        for line in resp.iter_lines():
            if line is None:
                continue
            if line == "":
                if len(buffer) > 0:
                    data_text = "\n".join(buffer)
                    buffer = []
                    try:
                        obj = json.loads(data_text)
                        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and ("result" in obj or "error" in obj):
                            return obj
                    except Exception:
                        # ignore non-JSON data events
                        pass
                continue
            if line.startswith("data:"):
                buffer.append(line[5:].lstrip())
            # ignore other SSE fields (event:, id:, retry:)
        # If we exit loop without finding response, return None
        return None

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        nonlocal msg_url_cache
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "request": payload, "url": url, "attempt": attempt + 1})
                with client.stream("POST", url, json=payload) as r:
                    status = r.status_code
                    ctype = r.headers.get("content-type", "")
                    if "text/event-stream" in ctype:
                        data = _parse_sse_response(r)
                        if data is None:
                            data = {"error": "No JSON-RPC response on SSE stream"}
                    else:
                        # Ensure body is read before accessing content on a streamed response
                        raw = r.read()
                        try:
                            data = json.loads(raw)
                        except Exception:
                            try:
                                data = raw.decode("utf-8", errors="replace")
                            except Exception:
                                data = str(raw)
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "recv", "status": status, "data": data, "attempt": attempt + 1})
                # Detect session errors and try to refresh session once
                if status in (400, 404):
                    err_obj = data if isinstance(data, dict) else {}
                    err_msg = ""
                    if isinstance(err_obj, dict):
                        e = err_obj.get("error")
                        if isinstance(e, dict):
                            err_msg = str(e.get("message") or "")
                    if ("session" in err_msg.lower()) or ("session id" in err_msg.lower()):
                        if verbose and trace is not None:
                            trace.append({"transport": "http", "direction": "info", "note": "session missing/invalid; re-initializing"})
                        # Re-discover endpoint and capture new session id
                        new_url, _ = _discover_endpoint()
                        if new_url is not None:
                            msg_url_cache = new_url
                            # Retry original request once immediately after refresh
                            with client.stream("POST", url, json=payload) as r2:
                                status2 = r2.status_code
                                ctype2 = r2.headers.get("content-type", "")
                                if "text/event-stream" in ctype2:
                                    data2 = _parse_sse_response(r2) or {"error": "No JSON-RPC response on SSE stream"}
                                else:
                                    raw2 = r2.read()
                                    try:
                                        data2 = json.loads(raw2)
                                    except Exception:
                                        try:
                                            data2 = raw2.decode("utf-8", errors="replace")
                                        except Exception:
                                            data2 = str(raw2)
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "recv", "status": status2, "data": data2, "note": "after re-init"})
                            return status2, data2
                return status, data
            except httpx.ReadTimeout as e:  # type: ignore[attr-defined]
                last_exc = e
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "error", "error": f"ReadTimeout on attempt {attempt + 1}"})
                continue
        # After retries, raise or return a structured error
        if last_exc is not None:
            return 599, {"error": f"ReadTimeout after retries: {last_exc}"}
        return 598, {"error": "Unknown error without exception"}

    def _discover_endpoint() -> Tuple[Optional[str], Dict[str, Any]]:
        # 1) If not explicitly in SSE mode, try base URL and trailing slash for initialize; capture Mcp-Session-Id if provided
        if transport != "sse":
            init_payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            for u in [base_url, base_url.rstrip("/") + "/"]:
                try:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": init_payload, "url": u, "note": "initialize"})
                    r = client.post(u, json=init_payload)
                    try:
                        data = r.json()
                    except Exception:
                        data = r.text
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "data": data, "headers": dict(r.headers)})
                    if isinstance(data, dict) and data.get("result"):
                        # Capture session id if present and attach to client for subsequent requests
                        sid = r.headers.get("Mcp-Session-Id")
                        if isinstance(sid, str) and sid:
                            client.headers["Mcp-Session-Id"] = sid
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "info", "note": "session id set", "session_id": sid})
                        return u, data
                except Exception:
                    continue
        # 2) If none worked, and SSE is hinted or allowed, try SSE handshake to discover legacy POST endpoint
        if transport in ("sse", "auto"):
            if transport == "sse":
                candidates = [
                    base_url.rstrip("/") + "/mcp/sse",
                    base_url.rstrip("/") + "/sse",
                ]
            else:
                candidates = [
                    base_url.rstrip("/") + "/mcp/sse",
                    base_url.rstrip("/") + "/sse",
                    base_url,
                    base_url.rstrip("/") + "/",
                    base_url.rstrip("/") + "/mcp",
                ]
            for sse_url in candidates:
                try:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "note": "sse-handshake"})
                    with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                        ctype = r.headers.get("content-type", "")
                        if "text/event-stream" not in ctype:
                            # Try to parse JSON body to extract a session id if server returns JSON
                            body_text = None
                            try:
                                raw = r.read()
                                body_text = raw.decode("utf-8", errors="replace")
                            except Exception:
                                body_text = None
                            session_from_body: Optional[str] = None
                            if body_text:
                                try:
                                    obj = json.loads(body_text)
                                    if isinstance(obj, dict):
                                        for k in ["sessionId", "session_id", "session", "mcp_session_id", "Mcp-Session-Id"]:
                                            v = obj.get(k)
                                            if isinstance(v, str) and v:
                                                session_from_body = v
                                                break
                                except Exception:
                                    pass
                            if verbose and trace is not None:
                                entry = {"transport": "http", "direction": "recv", "status": r.status_code, "headers": dict(r.headers), "note": "not sse"}
                                if session_from_body:
                                    entry["session_from_body"] = session_from_body
                                trace.append(entry)
                            # If we found a body-provided session id, set header for subsequent requests
                            if session_from_body:
                                client.headers["Mcp-Session-Id"] = session_from_body
                                if verbose and trace is not None:
                                    trace.append({"transport": "http", "direction": "info", "note": "session id set from JSON body", "session_id": session_from_body})
                            continue
                        # Read initial SSE events looking for an endpoint event or data containing post path/url
                        event_name: Optional[str] = None
                        buffer: List[str] = []
                        for line in r.iter_lines():
                            if line is None:
                                continue
                            if line.startswith("event:"):
                                event_name = line.split(":", 1)[1].strip()
                            elif line.startswith("data:"):
                                buffer.append(line[5:].lstrip())
                            elif line == "":
                                if len(buffer) > 0:
                                    data_text = "\n".join(buffer)
                                    buffer = []
                                    try:
                                        obj = json.loads(data_text)
                                    except Exception:
                                        obj = None
                                    if event_name == "endpoint" or isinstance(obj, dict):
                                        # Try to extract post path/url and session id
                                        post: Optional[str] = None
                                        sid: Optional[str] = None
                                        if isinstance(obj, dict):
                                            for key in ["post_path", "post_url", "path", "url", "endpoint"]:
                                                val = obj.get(key)
                                                if isinstance(val, str) and val:
                                                    post = val
                                                    break
                                        if post is None:
                                            # Many servers send plain text path in data, e.g. "/messages?sessionId=..."
                                            post = data_text.strip()
                                        # Extract sessionId from query if present
                                        try:
                                            parsed = urlparse(post)
                                            q = parse_qs(parsed.query)
                                            for k in ["sessionId", "session_id"]:
                                                if k in q and isinstance(q[k], list) and len(q[k]) > 0:
                                                    sid = q[k][0]
                                                    break
                                        except Exception:
                                            sid = None
                                        if isinstance(sid, str) and sid:
                                            client.headers["Mcp-Session-Id"] = sid
                                            if verbose and trace is not None:
                                                trace.append({"transport": "http", "direction": "info", "note": "session id set from SSE data", "session_id": sid})
                                        if isinstance(post, str):
                                            if post.startswith("http://") or post.startswith("https://"):
                                                return post, {"result": {"capabilities": {}}}
                                            # Build absolute URL from base origin
                                            base = base_url.rstrip("/")
                                            if not post.startswith("/"):
                                                post = "/" + post
                                            return base + post, {"result": {"capabilities": {}}}
                                # reset event name on dispatch boundary
                                event_name = None
                        # If we reach here, try next candidate
                except Exception as e:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "error", "error": f"sse-handshake-failed:{type(e).__name__}:{e}"})
                    continue
        # 3) If none worked, as a last resort on HTTP transport, try common legacy MCP POST endpoints
        if transport != "sse":
            init_payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            for path in ["/mcp", "/rpc"]:
                u = base_url.rstrip("/") + path
                try:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": init_payload, "url": u, "note": "initialize-legacy"})
                    r = client.post(u, json=init_payload)
                    try:
                        data = r.json()
                    except Exception:
                        data = r.text
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "recv", "status": r.status_code, "data": data, "headers": dict(r.headers)})
                    if isinstance(data, dict) and data.get("result"):
                        sid = r.headers.get("Mcp-Session-Id")
                        if isinstance(sid, str) and sid:
                            client.headers["Mcp-Session-Id"] = sid
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "info", "note": "session id set", "session_id": sid})
                        return u, data
                    # If server complains about missing/invalid session id, try to acquire one via GET and retry once
                    if isinstance(data, dict) and "error" in data:
                        err = data.get("error")
                        msg = (err.get("message") if isinstance(err, dict) else None) or ""
                        if isinstance(msg, str) and ("session" in msg.lower()):
                            try:
                                # GET without SSE accept to fetch potential JSON with session or header
                                if verbose and trace is not None:
                                    trace.append({"transport": "http", "direction": "send", "method": "GET", "url": u, "note": "fetch-session"})
                                g = client.get(u)
                                sid = g.headers.get("Mcp-Session-Id")
                                session_from_body = None
                                try:
                                    jobj = g.json()
                                    if isinstance(jobj, dict):
                                        for k in ["sessionId", "session_id", "session", "mcp_session_id", "Mcp-Session-Id"]:
                                            v = jobj.get(k)
                                            if isinstance(v, str) and v:
                                                session_from_body = v
                                                break
                                except Exception:
                                    pass
                                if isinstance(sid, str) and sid:
                                    client.headers["Mcp-Session-Id"] = sid
                                elif session_from_body:
                                    client.headers["Mcp-Session-Id"] = session_from_body
                                if verbose and trace is not None:
                                    trace.append({"transport": "http", "direction": "recv", "status": g.status_code, "headers": dict(g.headers), "note": "session fetch result", "session_header": sid, "session_body": session_from_body})
                                # Retry initialize once
                                r2 = client.post(u, json=init_payload)
                                try:
                                    data2 = r2.json()
                                except Exception:
                                    data2 = r2.text
                                if verbose and trace is not None:
                                    trace.append({"transport": "http", "direction": "recv", "status": r2.status_code, "data": data2, "note": "initialize-legacy-retry"})
                                if isinstance(data2, dict) and data2.get("result"):
                                    return u, data2
                            except Exception:
                                pass
                except Exception:
                    continue
        # 4) If none worked, return None
        return None, {}

    def _refine_with_capabilities(curr_url: str, init_obj: Dict[str, Any]) -> str:
        # Extract path-like strings and probe {cap}, {cap}/message, {cap}/list
        caps = (init_obj.get("result", {}) if isinstance(init_obj, dict) else {}).get("capabilities", {})
        paths: List[str] = []
        def _collect(obj: Any) -> None:
            if isinstance(obj, dict):
                for v in obj.values():
                    _collect(v)
            elif isinstance(obj, list):
                for v in obj:
                    _collect(v)
            elif isinstance(obj, str) and obj.startswith("/"):
                paths.append(obj)
        _collect(caps)
        for p in paths:
            for candidate in [
                base_url.rstrip("/") + p,
                (base_url.rstrip("/") + p).rstrip("/") + "/message",
                (base_url.rstrip("/") + p).rstrip("/") + "/list",
            ]:
                try:
                    status, data = _post_json(candidate, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    if isinstance(data, dict) and (data.get("result") or data.get("error")):
                        return candidate
                except Exception:
                    continue
        return curr_url

    try:
        # T-02/T-01/KF-03
        findings.extend(scan_http_base(base_url, spec_index, headers=headers, trace=trace, verbose=verbose, timeout=timeout))

        # Endpoint discovery via initialize only
        msg_url_cache, init_obj = _discover_endpoint()
        if msg_url_cache is None:
            # Unable to initialize at base; record minimal A-01 failure and abort further probes
            a01 = spec_index.get("A-01")
            if a01:
                findings.append(_finding(a01, passed=False, details="initialize failed at base URL (no endpoint)"))
            return findings
        # refine using capabilities if present
        msg_url_cache = _refine_with_capabilities(msg_url_cache, init_obj)

        # A-01: Unauthenticated access (probe again without auth only if headers were provided)
        a01 = spec_index.get("A-01")
        if a01:
            try:
                status, data = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
                is_denied = status in (401, 403)
                details = f"status={status}, body={(json.dumps(data)[:200] + '...') if isinstance(data, (dict, list)) else (str(data)[:200] + '...')}"
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
                # Initialize already done above; try altered session id on discovered endpoint
                status_init, _ = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}})
                sess_ok = status_init < 500
                bad_headers = dict(client.headers)
                if "Mcp-Session-Id" not in bad_headers:
                    bad_headers["Mcp-Session-Id"] = "tampered-session"
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "request": {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, "url": msg_url_cache, "note": "altered session id"})
                bad = client.post(msg_url_cache, json={"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}, headers=bad_headers)
                rejects_bad = bad.status_code in (401, 403, 400)
                findings.append(_finding(t03, passed=(sess_ok and rejects_bad), details=f"bad_status={bad.status_code}"))
            except Exception as e:
                findings.append(_finding(t03, passed=False, details=f"error={type(e).__name__}:{e}"))

        # rpc using discovered endpoint only
        def rpc(method: str, params: Dict[str, object]) -> Dict[str, object]:
            status, data = _post_json(msg_url_cache, {"jsonrpc": "2.0", "id": 99, "method": method, "params": params})
            return data if isinstance(data, dict) else {"status": status, "body": data}

        # BASE-01 already done; record it properly
        base = spec_index.get("BASE-01")
        if base:
            ok = isinstance(init_obj, dict) and "result" in init_obj and "capabilities" in init_obj.get("result", {})
            findings.append(_finding(base, ok, json.dumps(init_obj)))

        # tools/list
        tools_list: Dict[str, Any] = rpc("tools/list", {})
        tools = tools_list.get("result", {}).get("tools", []) if isinstance(tools_list, dict) else []

        # RC-01: Remote access control exposure
        rc01 = spec_index.get("RC-01")
        if rc01 and isinstance(tools, list):
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

        # P-02 Prompt/description heuristics
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

        # P-01 Prompt argument validation
        p01 = spec_index.get("P-01")
        if p01:
            p01_issues: List[Dict[str, Any]] = []
            try:
                plist = rpc("prompts/list", {})
                prompts = plist.get("result", {}).get("prompts", []) if isinstance(plist, dict) else []
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
                findings.append(_finding(p01, passed=len(p01_issues) == 0, details=json.dumps(p01_issues)))
            except Exception as e:
                findings.append(_finding(p01, passed=False, details=f"error={type(e).__name__}:{e}"))

        # X-01 risky unconstrained tools
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
        rlist = rpc("resources/list", {})
        resources = rlist.get("result", {}).get("resources", []) if isinstance(rlist, dict) else []

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
            findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)))

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
            findings.append(_finding(r05, passed=len(leaks) == 0, details=json.dumps(leaks)))

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
            findings.append(_finding(r04, passed=len(issues) == 0, details=json.dumps(issues)))

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
                findings.append(_finding(p03, passed=len(p03_hits) == 0, details=json.dumps(p03_hits)))
            except Exception as e:
                findings.append(_finding(p03, passed=False, details=f"error={type(e).__name__}:{e}"))

        # A-03 token pass-through via tool
        a03 = spec_index.get("A-03")
        if a03:
            leak = rpc("tools/call", {"name": "upstream_access", "arguments": {"code": "dummy"}})
            text = json.dumps(leak).lower()
            leaked = any(k in text for k in ["access_token", "sk-", "token-body", "bearer "])
            findings.append(_finding(a03, passed=not leaked, details=json.dumps(leak)))

    finally:
        client.close()
    return findings


