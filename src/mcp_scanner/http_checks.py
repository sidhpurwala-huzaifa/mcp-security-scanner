from __future__ import annotations

from typing import Dict, List, Optional, Any, Tuple
import json
import time

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
            passed = False
            details = f"error={type(e).__name__}:{e}"
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
                    passed=True,
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
                    passed=True,
                    details=f"warn: local-only heuristic; error={type(e).__name__}:{e}",
                    remediation=kf03.remediation,
                    references=kf03.references,
                )
            )

    client.close()
    return findings


def run_full_http_checks(base_url: str, spec_index: Dict[str, SpecCheck], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> List[Finding]:
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

    # Cache discovered message URL and working SSE URL (legacy) and allow refresh from inner helpers
    msg_url_cache: Optional[str] = None
    sse_url_cache: Optional[str] = None
    # Persistent SSE stream state (legacy servers): keep alive, resume on disconnect
    sse_stream: Optional[httpx.Response] = None
    last_event_id: Optional[str] = None

    def _parse_sse_response(resp: httpx.Response) -> Any:
        # Parse SSE and return the first JSON-RPC response object encountered
        buffer: List[str] = []
        for line in resp.iter_lines():
            if line is None:
                continue
            # Emit raw SSE line in verbose mode for debugging
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "raw": line, "note": "sse-line"})
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

    def _close_sse_stream() -> None:
        nonlocal sse_stream
        if sse_stream is not None:
            try:
                sse_stream.close()
            except Exception:
                pass
            sse_stream = None

    def _open_sse_stream() -> None:
        nonlocal sse_stream, last_event_id
        if sse_url_cache is None:
            return
        headers = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
        sid = client.headers.get("Mcp-Session-Id")
        if isinstance(sid, str) and sid:
            headers["Mcp-Session-Id"] = sid
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id
        req = client.build_request("GET", sse_url_cache, headers=headers)
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url_cache, "note": "sse-open", "headers": headers})
        resp = client.send(req, stream=True)
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" not in ctype:
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": resp.status_code, "headers": dict(resp.headers), "note": "sse-open-not-sse"})
            try:
                resp.close()
            except Exception:
                pass
            return
        sse_stream = resp
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "info", "note": "sse-opened"})

    def _ensure_sse_stream() -> None:
        if sse_stream is None:
            _open_sse_stream()

    def _wait_sse_response(sse_url: str, expected_id: Any) -> Any:
        # Ensure persistent SSE stream is available; reopen on disconnect and resume using Last-Event-ID
        nonlocal last_event_id
        nonlocal msg_url_cache
        _ensure_sse_stream()
        if sse_stream is None:
            return {"error": "SSE stream not available"}
        buffer: List[str] = []
        current_event_id: Optional[str] = None
        event_name: Optional[str] = None
        deadline = time.time() + timeout
        while True:
            try:
                for line in sse_stream.iter_lines():
                    if line is None:
                        continue
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "recv", "raw": line, "note": "sse-line"})
                    if line.startswith("event:"):
                        event_name = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("id:"):
                        current_event_id = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        buffer.append(line[5:].lstrip())
                    elif line == "":
                        if buffer:
                            data_text = "\n".join(buffer)
                            buffer = []
                            # Handle endpoint rotation events (plain text endpoint in data)
                            if event_name == "endpoint":
                                candidate = data_text.strip()
                                try:
                                    parsed = urlparse(candidate)
                                    q = parse_qs(parsed.query)
                                    sid: Optional[str] = None
                                    for k in ["sessionId", "session_id"]:
                                        if k in q and isinstance(q[k], list) and q[k]:
                                            sid = q[k][0]
                                            break
                                    if sid:
                                        client.headers["Mcp-Session-Id"] = sid
                                        if candidate.startswith("http://") or candidate.startswith("https://"):
                                            msg_url_cache = candidate
                                        else:
                                            base = base_url.rstrip("/")
                                            if not candidate.startswith("/"):
                                                candidate = "/" + candidate
                                            msg_url_cache = base + candidate
                                        if verbose and trace is not None:
                                            trace.append({"transport": "http", "direction": "info", "note": "endpoint rotated", "msg_url": msg_url_cache, "session_id": sid})
                                        # Signal rotation to caller so it can resend to new endpoint
                                        return {"_endpoint_rotated": True}
                                except Exception:
                                    pass
                                event_name = None
                                continue
                            # Try parse JSON-RPC response
                            try:
                                obj = json.loads(data_text)
                            except Exception:
                                obj = None
                            if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and ("result" in obj or "error" in obj):
                                if obj.get("id") == expected_id:
                                    if current_event_id:
                                        last_event_id = current_event_id
                                    if verbose and trace is not None:
                                        trace.append({"transport": "http", "direction": "recv", "status": 200, "data": obj, "note": "sse-response"})
                                    return obj
                        if current_event_id:
                            last_event_id = current_event_id
                        current_event_id = None
                        event_name = None
                # If we exit the for-loop, the stream likely closed; reconnect
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}
                if time.time() > deadline:
                    return {"error": "Timeout waiting for SSE response"}
            except Exception:
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}
                if time.time() > deadline:
                    return {"error": "Timeout waiting for SSE response"}

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        nonlocal msg_url_cache
        nonlocal sse_url_cache
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "request": payload, "url": url, "attempt": attempt + 1})
                # If posting to a legacy SSE session endpoint (sessionId in URL), require SSE response
                post_headers = None
                if "sessionId=" in url:
                    post_headers = dict(client.headers)
                    post_headers["Accept"] = "text/event-stream"
                with client.stream("POST", url, json=payload, headers=post_headers) as r:
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
                # If legacy SSE server returns 202 Accepted and responses go over separate SSE stream, wait for matching SSE response
                if (status == 202 or (isinstance(data, str) and data.strip().lower().startswith("accepted"))) and sse_url_cache:
                    expected_id = payload.get("id") if isinstance(payload, dict) else None
                    if expected_id is not None:
                        data = _wait_sse_response(sse_url_cache, expected_id)
                        # If endpoint rotated, retry POST at updated msg_url
                        if isinstance(data, dict) and data.get("_endpoint_rotated") and isinstance(msg_url_cache, str):
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "info", "note": "retry after endpoint rotate", "url": msg_url_cache})
                            url = msg_url_cache
                            continue
                        return 200, data
                # Detect session errors and try to refresh session once
                if status in (400, 404):
                    err_obj = data if isinstance(data, dict) else {}
                    err_msg = ""
                    if isinstance(err_obj, dict):
                        e = err_obj.get("error")
                        if isinstance(e, dict):
                            err_msg = str(e.get("message") or "")
                    low = err_msg.lower()
                    if (("session" in low) or ("session id" in low)) and ("different transport" not in low):
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
                            if (status2 == 202 or (isinstance(data2, str) and data2.strip().lower().startswith("accepted"))) and sse_url_cache:
                                expected_id = payload.get("id") if isinstance(payload, dict) else None
                                if expected_id is not None:
                                    data2 = _wait_sse_response(sse_url_cache, expected_id)
                                    return 200, data2
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
        nonlocal sse_url_cache
        # Use only the provided URL(s); no alternate probing
        if transport == "sse":
            sse_url = (base_url.rstrip("/") + sse_endpoint) if sse_endpoint else base_url
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "note": "sse-handshake"})
                with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                    if "text/event-stream" not in r.headers.get("content-type", ""):
                        return None, {}
                    sse_url_cache = sse_url
                    event_name: Optional[str] = None
                    buffer: List[str] = []
                    for line in r.iter_lines():
                        if line is None:
                            continue
                        if verbose and trace is not None:
                            trace.append({"transport": "http", "direction": "recv", "raw": line, "note": "sse-line"})
                        if line.startswith("event:"):
                            event_name = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            buffer.append(line[5:].lstrip())
                        elif line == "":
                            if buffer:
                                data_text = "\n".join(buffer)
                                buffer = []
                                try:
                                    obj = json.loads(data_text)
                                except Exception:
                                    obj = None
                                post: Optional[str] = None
                                sid: Optional[str] = None
                                if isinstance(obj, dict):
                                    for key in ["post_path", "post_url", "path", "url", "endpoint"]:
                                        val = obj.get(key)
                                        if isinstance(val, str) and val:
                                            post = val
                                            break
                                if post is None and (event_name == "endpoint"):
                                    post = data_text.strip()
                                if post:
                                    try:
                                        parsed = urlparse(post)
                                        q = parse_qs(parsed.query)
                                        for k in ["sessionId", "session_id"]:
                                            if k in q and isinstance(q[k], list) and q[k]:
                                                sid = q[k][0]
                                                break
                                    except Exception:
                                        sid = None
                                    if isinstance(sid, str) and sid:
                                        client.headers["Mcp-Session-Id"] = sid
                                        if verbose and trace is not None:
                                            trace.append({"transport": "http", "direction": "info", "note": "session id set from SSE data", "session_id": sid})
                                    if post.startswith("http://") or post.startswith("https://"):
                                        return post, {"result": {"capabilities": {}}}
                                    base = base_url.rstrip("/")
                                    if not post.startswith("/"):
                                        post = "/" + post
                                    return base + post, {"result": {"capabilities": {}}}
                            event_name = None
                    # If no endpoint provided, try header-derived session id to synthesize
                    sid_hdr = client.headers.get("Mcp-Session-Id")
                    if isinstance(sid_hdr, str) and sid_hdr:
                        return base_url.rstrip("/") + "/messages?sessionId=" + sid_hdr, {"result": {"capabilities": {}}}
            except Exception:
                return None, {}
            return None, {}
        # HTTP: use provided base_url directly
        init_payload = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}}, "clientInfo": {"name": "mcp-security-scanner", "version": "0.16.5"}}}
        try:
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "send", "request": init_payload, "url": base_url, "note": "initialize"})
            # Stream response to handle servers that reply with text/event-stream for initialize
            with client.stream("POST", base_url, json=init_payload) as r:
                ctype = r.headers.get("content-type", "")
                if "text/event-stream" in ctype:
                    data_obj = _parse_sse_response(r) or {}
                else:
                    raw = r.read()
                    try:
                        data_obj = json.loads(raw)
                    except Exception:
                        try:
                            data_obj = raw.decode("utf-8", errors="replace")
                        except Exception:
                            data_obj = str(raw)
                if verbose and trace is not None:
                    entry = {"transport": "http", "direction": "recv", "status": r.status_code, "headers": dict(r.headers)}
                    if isinstance(data_obj, (dict, list)):
                        entry["data"] = data_obj
                    else:
                        entry["data"] = str(data_obj)[:500]
                    trace.append(entry)
                sid = r.headers.get("Mcp-Session-Id")
                if isinstance(sid, str) and sid:
                    client.headers["Mcp-Session-Id"] = sid
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "info", "note": "session id set", "session_id": sid})
            return base_url, data_obj if isinstance(data_obj, dict) else {}
        except Exception:
            return base_url, {}

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

        # Endpoint selection relies solely on provided URLs; skip capability-based refinement
        msg_url_cache, init_obj = _discover_endpoint()
        if msg_url_cache is None:
            a01 = spec_index.get("A-01")
            if a01:
                findings.append(_finding(a01, passed=False, details="initialize failed at provided URL (no endpoint)"))
            return findings
        # For legacy SSE session endpoints, open persistent SSE
        if sse_url_cache and isinstance(msg_url_cache, str) and ("sessionId=" in msg_url_cache):
            _open_sse_stream()

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
                # For legacy SSE sessions, skip tampering to avoid invalidating the server session
                if "sessionId=" in (msg_url_cache or ""):
                    findings.append(_finding(t03, passed=True, details="skipped on legacy SSE session endpoint"))
                else:
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

        # tools/list (guard against null result)
        tools_list: Dict[str, Any] = rpc("tools/list", {})
        tools_result = (tools_list.get("result") if isinstance(tools_list, dict) else None) or {}
        tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []

        # RC-01: Remote access control exposure
        rc01 = spec_index.get("RC-01")
        if rc01 and isinstance(tools, list):
            if len(tools) == 0:
                findings.append(_finding(rc01, passed=True, details="No tools were discovered"))
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
                findings.append(_finding(x03, passed=True, details="No tools were discovered"))
            else:
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
            if len(tools) == 0:
                findings.append(_finding(p02, passed=True, details="No tools were discovered"))
            else:
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
                prompts_result = (plist.get("result") if isinstance(plist, dict) else None) or {}
                prompts = prompts_result.get("prompts", []) if isinstance(prompts_result, dict) else []
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
            if not tools:
                findings.append(_finding(x01, passed=True, details="No tools were discovered"))
            else:
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
            if len(tools) == 0:
                findings.append(_finding(x02, passed=True, details="No tools were discovered"))
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
        rlist = rpc("resources/list", {})
        resources_result = (rlist.get("result") if isinstance(rlist, dict) else None) or {}
        resources = resources_result.get("resources", []) if isinstance(resources_result, dict) else []

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


def rpc_call(base_url: str, method: str, params: Dict[str, Any], headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> Dict[str, Any]:
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )
    client.headers.setdefault("Accept", "application/json, text/event-stream")
    client.headers.setdefault("MCP-Protocol-Version", "2025-06-18")

    msg_url_cache: Optional[str] = None
    sse_url_cache: Optional[str] = None
    sse_stream: Optional[httpx.Response] = None
    last_event_id: Optional[str] = None

    def _parse_sse_response(resp: httpx.Response) -> Any:
        buffer: List[str] = []
        for line in resp.iter_lines():
            if line is None:
                continue
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "raw": line, "note": "sse-line"})
            if line == "":
                if buffer:
                    data_text = "\n".join(buffer)
                    buffer = []
                    try:
                        obj = json.loads(data_text)
                        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and ("result" in obj or "error" in obj):
                            return obj
                    except Exception:
                        pass
                continue
            if line.startswith("data:"):
                buffer.append(line[5:].lstrip())
        return None

    def _close_sse_stream() -> None:
        nonlocal sse_stream
        if sse_stream is not None:
            try:
                sse_stream.close()
            except Exception:
                pass
            sse_stream = None

    def _open_sse_stream() -> None:
        nonlocal sse_stream, last_event_id
        if sse_url_cache is None:
            return
        headers2 = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
        sid = client.headers.get("Mcp-Session-Id")
        if isinstance(sid, str) and sid:
            headers2["Mcp-Session-Id"] = sid
        if last_event_id:
            headers2["Last-Event-ID"] = last_event_id
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url_cache, "note": "sse-open", "headers": headers2})
        resp = client.send(client.build_request("GET", sse_url_cache, headers=headers2), stream=True)
        if "text/event-stream" not in resp.headers.get("content-type", ""):
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": resp.status_code, "headers": dict(resp.headers), "note": "sse-open-not-sse"})
            try:
                resp.close()
            except Exception:
                pass
            return
        sse_stream = resp
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "info", "note": "sse-opened"})

    def _ensure_sse_stream() -> None:
        if sse_stream is None:
            _open_sse_stream()

    def _wait_sse_response(sse_url: str, expected_id: Any) -> Any:
        nonlocal last_event_id, msg_url_cache
        _ensure_sse_stream()
        if sse_stream is None:
            return {"error": "SSE stream not available"}
        buffer: List[str] = []
        current_event_id: Optional[str] = None
        event_name: Optional[str] = None
        deadline = time.time() + timeout
        while True:
            try:
                for line in sse_stream.iter_lines():
                    if line is None:
                        continue
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "recv", "raw": line, "note": "sse-line"})
                    if line.startswith("event:"):
                        event_name = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("id:"):
                        current_event_id = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        buffer.append(line[5:].lstrip())
                    elif line == "":
                        if buffer:
                            data_text = "\n".join(buffer)
                            buffer = []
                            if event_name == "endpoint":
                                candidate = data_text.strip()
                                try:
                                    parsed = urlparse(candidate)
                                    q = parse_qs(parsed.query)
                                    sid: Optional[str] = None
                                    for k in ["sessionId", "session_id"]:
                                        if k in q and isinstance(q[k], list) and q[k]:
                                            sid = q[k][0]
                                            break
                                    if sid:
                                        client.headers["Mcp-Session-Id"] = sid
                                        if candidate.startswith("http://") or candidate.startswith("https://"):
                                            msg_url_cache = candidate
                                        else:
                                            base = base_url.rstrip("/")
                                            if not candidate.startswith("/"):
                                                candidate = "/" + candidate
                                            msg_url_cache = base + candidate
                                        if verbose and trace is not None:
                                            trace.append({"transport": "http", "direction": "info", "note": "endpoint rotated", "msg_url": msg_url_cache, "session_id": sid})
                                        return {"_endpoint_rotated": True}
                                except Exception:
                                    pass
                                event_name = None
                                continue
                            try:
                                obj = json.loads(data_text)
                            except Exception:
                                obj = None
                            if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and ("result" in obj or "error" in obj):
                                if obj.get("id") == expected_id:
                                    if current_event_id:
                                        last_event_id = current_event_id
                                    if verbose and trace is not None:
                                        trace.append({"transport": "http", "direction": "recv", "status": 200, "data": obj, "note": "sse-response"})
                                    return obj
                        if current_event_id:
                            last_event_id = current_event_id
                        current_event_id = None
                        event_name = None
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}
                if time.time() > deadline:
                    return {"error": "Timeout waiting for SSE response"}
            except Exception:
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}
                if time.time() > deadline:
                    return {"error": "Timeout waiting for SSE response"}

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        nonlocal msg_url_cache
        nonlocal sse_url_cache
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "request": payload, "url": url, "attempt": attempt + 1})
                post_headers = None
                if "sessionId=" in url:
                    post_headers = dict(client.headers)
                    post_headers["Accept"] = "text/event-stream"
                with client.stream("POST", url, json=payload, headers=post_headers) as r:
                    status = r.status_code
                    ctype = r.headers.get("content-type", "")
                    if "text/event-stream" in ctype:
                        data = _parse_sse_response(r)
                        if data is None:
                            data = {"error": "No JSON-RPC response on SSE stream"}
                    else:
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
                if (status == 202 or (isinstance(data, str) and data.strip().lower().startswith("accepted"))) and sse_url_cache:
                    expected_id = payload.get("id") if isinstance(payload, dict) else None
                    if expected_id is not None:
                        data = _wait_sse_response(sse_url_cache, expected_id)
                        if isinstance(data, dict) and data.get("_endpoint_rotated") and isinstance(msg_url_cache, str):
                            if verbose and trace is not None:
                                trace.append({"transport": "http", "direction": "info", "note": "retry after endpoint rotate", "url": msg_url_cache})
                            url = msg_url_cache
                            continue
                        return 200, data
                return status, data
            except httpx.ReadTimeout as e:  # type: ignore[attr-defined]
                last_exc = e
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "error", "error": f"ReadTimeout on attempt {attempt + 1}"})
                continue
        if last_exc is not None:
            return 599, {"error": f"ReadTimeout after retries: {last_exc}"}
        return 598, {"error": "Unknown error without exception"}

    def _discover_endpoint() -> Tuple[Optional[str], Dict[str, Any]]:
        # base POST initialize (streamable HTTP)
        if transport != "sse":
            init_payload = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}}, "clientInfo": {"name": "mcp-security-scanner", "version": "0.16.5"}}}
            for u in [base_url]:
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
                    if isinstance(data, dict):
                        sid = r.headers.get("Mcp-Session-Id")
                        if isinstance(sid, str) and sid:
                            client.headers["Mcp-Session-Id"] = sid
                        return u, data
                except Exception:
                    continue
        # legacy HTTP+SSE handshake (explicit URL only)
        if transport in ("sse", "auto"):
            sse_url = (base_url.rstrip("/") + sse_endpoint) if (transport == "sse" and sse_endpoint) else base_url
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "note": "sse-handshake"})
                with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                    if "text/event-stream" not in r.headers.get("content-type", ""):
                        return None, {}
                    buffer: List[str] = []
                    event_name: Optional[str] = None
                    for line in r.iter_lines():
                        if line is None:
                            continue
                        if line.startswith("event:"):
                            event_name = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            buffer.append(line[5:].lstrip())
                        elif line == "":
                            if buffer:
                                data_text = "\n".join(buffer)
                                buffer = []
                                try:
                                    obj = json.loads(data_text)
                                except Exception:
                                    obj = None
                                post: Optional[str] = None
                                sid: Optional[str] = None
                                if isinstance(obj, dict):
                                    for key in ["post_path", "post_url", "path", "url", "endpoint"]:
                                        val = obj.get(key)
                                        if isinstance(val, str) and val:
                                            post = val
                                            break
                                if post is None and (event_name == "endpoint"):
                                    post = data_text.strip()
                                if post:
                                    try:
                                        parsed = urlparse(post)
                                        q = parse_qs(parsed.query)
                                        for k in ["sessionId", "session_id"]:
                                            if k in q and isinstance(q[k], list) and q[k]:
                                                sid = q[k][0]
                                                break
                                    except Exception:
                                        sid = None
                                    if isinstance(sid, str) and sid:
                                        client.headers["Mcp-Session-Id"] = sid
                                    if post.startswith("http://") or post.startswith("https://"):
                                        return post, {"result": {"capabilities": {}}}
                                    base = base_url.rstrip("/")
                                    if not post.startswith("/"):
                                        post = "/" + post
                                    return base + post, {"result": {"capabilities": {}}}
                            event_name = None
                    sid_hdr = client.headers.get("Mcp-Session-Id")
                    if isinstance(sid_hdr, str) and sid_hdr:
                        return base_url.rstrip("/") + "/messages?sessionId=" + sid_hdr, {"result": {"capabilities": {}}}
            except Exception:
                return None, {}
        return None, {}

    try:
        msg_url, init_obj = _discover_endpoint()
        if msg_url is None:
            return {"error": "No endpoint discovered"}
        # No capability-based refinement; use discovered or provided URL directly
        if sse_url_cache and ("sessionId=" in (msg_url or "")):
            _open_sse_stream()
        payload = {"jsonrpc": "2.0", "id": 99, "method": method, "params": params}
        status, data = _post_json(msg_url, payload)
        if isinstance(data, dict):
            return data
        return {"status": status, "body": data}
    finally:
        _close_sse_stream()
        client.close()


def get_server_health(base_url: str, headers: Optional[Dict[str, str]] = None, trace: Optional[List[Dict[str, Any]]] = None, verbose: bool = False, timeout: float = 12.0, transport: str = "auto", sse_endpoint: Optional[str] = None) -> Dict[str, Any]:
    """Return endpoints and enumerations for debugging: msg endpoint, optional SSE url, init object, tools, prompts, resources.
    Works with legacy HTTP+SSE and streamable HTTP."""
    client = httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=3.0, read=timeout, write=timeout, pool=timeout),
        headers=headers or {},
    )
    client.headers.setdefault("Accept", "application/json, text/event-stream")
    client.headers.setdefault("MCP-Protocol-Version", "2025-06-18")
    msg_url_cache: Optional[str] = None
    sse_url_cache: Optional[str] = None
    # Persistent SSE state for legacy servers
    sse_stream: Optional[httpx.Response] = None
    last_event_id: Optional[str] = None

    def _parse_sse_response(resp: httpx.Response) -> Any:
        buffer: List[str] = []
        for line in resp.iter_lines():
            if line is None:
                continue
            if line == "":
                if buffer:
                    data_text = "\n".join(buffer)
                    buffer = []
                    try:
                        obj = json.loads(data_text)
                        if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and ("result" in obj or "error" in obj):
                            return obj
                    except Exception:
                        pass
                continue
            if line.startswith("data:"):
                buffer.append(line[5:].lstrip())
        return None

    def _close_sse_stream() -> None:
        nonlocal sse_stream
        if sse_stream is not None:
            try:
                sse_stream.close()
            except Exception:
                pass
            sse_stream = None

    def _open_sse_stream() -> None:
        nonlocal sse_stream, last_event_id
        if sse_url_cache is None:
            return
        headers2 = {"Accept": "text/event-stream", "Cache-Control": "no-cache"}
        sid = client.headers.get("Mcp-Session-Id")
        if isinstance(sid, str) and sid:
            headers2["Mcp-Session-Id"] = sid
        if last_event_id:
            headers2["Last-Event-ID"] = last_event_id
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url_cache, "note": "sse-open", "headers": headers2})
        resp = client.send(client.build_request("GET", sse_url_cache, headers=headers2), stream=True)
        if "text/event-stream" not in resp.headers.get("content-type", ""):
            if verbose and trace is not None:
                trace.append({"transport": "http", "direction": "recv", "status": resp.status_code, "headers": dict(resp.headers), "note": "sse-open-not-sse"})
            try:
                resp.close()
            except Exception:
                pass
            return
        sse_stream = resp
        if verbose and trace is not None:
            trace.append({"transport": "http", "direction": "info", "note": "sse-opened"})

    def _ensure_sse_stream() -> None:
        if sse_stream is None:
            _open_sse_stream()

    def _wait_sse_response(sse_url: str, expected_id: Any) -> Any:
        nonlocal last_event_id
        _ensure_sse_stream()
        if sse_stream is None:
            return {"error": "SSE stream not available"}
        buffer: List[str] = []
        current_event_id: Optional[str] = None
        while True:
            try:
                for line in sse_stream.iter_lines():
                    if line is None:
                        continue
                    if line.startswith("id:"):
                        current_event_id = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        buffer.append(line[5:].lstrip())
                    elif line == "":
                        if buffer:
                            data_text = "\n".join(buffer)
                            buffer = []
                            try:
                                obj = json.loads(data_text)
                            except Exception:
                                obj = None
                            if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" and obj.get("id") == expected_id:
                                if current_event_id:
                                    last_event_id = current_event_id
                                return obj
                        if current_event_id:
                            last_event_id = current_event_id
                        current_event_id = None
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}
            except Exception:
                _close_sse_stream()
                _open_sse_stream()
                if sse_stream is None:
                    return {"error": "Unable to reopen SSE stream"}

    def _post_json(url: str, payload: Dict[str, Any]) -> Tuple[int, Any]:
        post_headers = None
        if "sessionId=" in url:
            post_headers = dict(client.headers)
            post_headers["Accept"] = "text/event-stream"
        with client.stream("POST", url, json=payload, headers=post_headers) as r:
            status = r.status_code
            ctype = r.headers.get("content-type", "")
            if "text/event-stream" in ctype:
                data = _parse_sse_response(r) or {"error": "No JSON-RPC response on SSE stream"}
            else:
                raw = r.read()
                try:
                    data = json.loads(raw)
                except Exception:
                    try:
                        data = raw.decode("utf-8", errors="replace")
                    except Exception:
                        data = str(raw)
        if (status == 202 or (isinstance(data, str) and data.strip().lower().startswith("accepted"))) and sse_url_cache:
            expected_id = payload.get("id")
            if expected_id is not None:
                data = _wait_sse_response(sse_url_cache, expected_id)
                return 200, data
        return status, data

    def _discover_endpoint() -> Tuple[Optional[str], Dict[str, Any]]:
        # base POST initialize (streamable HTTP)
        if transport != "sse":
            init_payload = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}}, "clientInfo": {"name": "mcp-security-scanner", "version": "0.16.5"}}}
            for u in [base_url]:
                try:
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "send", "request": init_payload, "url": u, "note": "initialize"})
                    # Stream to support SSE initialize responses
                    with client.stream("POST", u, json=init_payload) as r:
                        if "text/event-stream" in r.headers.get("content-type", ""):
                            data = _parse_sse_response(r) or {}
                        else:
                            raw = r.read()
                            try:
                                data = json.loads(raw)
                            except Exception:
                                try:
                                    data = raw.decode("utf-8", errors="replace")
                                except Exception:
                                    data = str(raw)
                    if verbose and trace is not None:
                        trace.append({"transport": "http", "direction": "recv", "status": 200, "data": data, "headers": dict(r.headers) if hasattr(r, 'headers') else {}})
                    if isinstance(data, dict):
                        sid = r.headers.get("Mcp-Session-Id")
                        if isinstance(sid, str) and sid:
                            client.headers["Mcp-Session-Id"] = sid
                        return u, data
                except Exception:
                    continue
        # legacy HTTP+SSE handshake (explicit URL only)
        if transport in ("sse", "auto"):
            sse_url = (base_url.rstrip("/") + sse_endpoint) if (transport == "sse" and sse_endpoint) else base_url
            try:
                if verbose and trace is not None:
                    trace.append({"transport": "http", "direction": "send", "method": "GET", "url": sse_url, "note": "sse-handshake"})
                with client.stream("GET", sse_url, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"}) as r:
                    if "text/event-stream" not in r.headers.get("content-type", ""):
                        return None, {}
                    buffer: List[str] = []
                    event_name: Optional[str] = None
                    for line in r.iter_lines():
                        if line is None:
                            continue
                        if line.startswith("event:"):
                            event_name = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            buffer.append(line[5:].lstrip())
                        elif line == "":
                            if buffer:
                                data_text = "\n".join(buffer)
                                buffer = []
                                try:
                                    obj = json.loads(data_text)
                                except Exception:
                                    obj = None
                                post: Optional[str] = None
                                sid: Optional[str] = None
                                if isinstance(obj, dict):
                                    for key in ["post_path", "post_url", "path", "url", "endpoint"]:
                                        val = obj.get(key)
                                        if isinstance(val, str) and val:
                                            post = val
                                            break
                                if post is None and (event_name == "endpoint"):
                                    post = data_text.strip()
                                if post:
                                    try:
                                        parsed = urlparse(post)
                                        q = parse_qs(parsed.query)
                                        for k in ["sessionId", "session_id"]:
                                            if k in q and isinstance(q[k], list) and q[k]:
                                                sid = q[k][0]
                                                break
                                    except Exception:
                                        sid = None
                                    if isinstance(sid, str) and sid:
                                        client.headers["Mcp-Session-Id"] = sid
                                    if post.startswith("http://") or post.startswith("https://"):
                                        return post, {"result": {"capabilities": {}}}
                                    base = base_url.rstrip("/")
                                    if not post.startswith("/"):
                                        post = "/" + post
                                    return base + post, {"result": {"capabilities": {}}}
                            event_name = None
                    sid_hdr = client.headers.get("Mcp-Session-Id")
                    if isinstance(sid_hdr, str) and sid_hdr:
                        return base_url.rstrip("/") + "/messages?sessionId=" + sid_hdr, {"result": {"capabilities": {}}}
            except Exception:
                return None, {}
        return None, {}

    try:
        init_url, init_obj = _discover_endpoint()
        if init_url is None:
            return {"base_url": base_url, "msg_url": None, "sse_url": None, "initialize": None, "tools": [], "prompts": [], "resources": []}
        msg_url = init_url
        if transport in ("sse", "auto") and ("sessionId=" in (msg_url or "")):
            _open_sse_stream()
        def rpc(method: str, params: Dict[str, object]) -> Dict[str, object]:
            status, data = _post_json(msg_url, {"jsonrpc": "2.0", "id": 99, "method": method, "params": params})
            return data if isinstance(data, dict) else {"status": status, "body": data}
        tools_obj = rpc("tools/list", {})
        tools_result = (tools_obj.get("result") if isinstance(tools_obj, dict) else None) or {}
        tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        prompts_obj = rpc("prompts/list", {})
        prompts_result = (prompts_obj.get("result") if isinstance(prompts_obj, dict) else None) or {}
        prompts = prompts_result.get("prompts", []) if isinstance(prompts_result, dict) else []
        resources_obj = rpc("resources/list", {})
        resources_result = (resources_obj.get("result") if isinstance(resources_obj, dict) else None) or {}
        resources = resources_result.get("resources", []) if isinstance(resources_result, dict) else []
        return {"base_url": base_url, "msg_url": msg_url, "sse_url": None, "initialize": init_obj, "tools": tools, "prompts": prompts, "resources": resources}
    finally:
        client.close()

