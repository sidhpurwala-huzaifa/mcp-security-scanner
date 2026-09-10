"""Synchronous Streamable HTTP lifecycle and correlated JSON/SSE exchanges.

Legacy GET/endpoint-event transport deliberately lives outside this module.
Requests are never replayed: a lost response may follow a completed tool call.
"""
import json
import re
import time
from importlib.metadata import PackageNotFoundError, version

from .redaction import redact_secrets


class SessionError(RuntimeError):
    pass


class SSEReader:
    """Incremental SSE events; retain unread events across legacy POST calls."""

    def __init__(self, response, max_bytes):
        self.chunks = response.iter_bytes()
        self.max_bytes = max_bytes
        self.pending = b""
        self.size = 0
        self.first_line = True
        self.eof = False
        self.skip_lf = False
        self.data = []
        self.event = "message"

    def next_event(self, deadline):
        while True:
            if time.monotonic() >= deadline:
                raise SessionError("Response deadline exceeded")
            if self.skip_lf and self.pending:
                self.pending = self.pending.removeprefix(b"\n")
                self.skip_lf = False
            delimiter = re.search(b"[\\r\\n]", self.pending)
            if delimiter is not None:
                pos = delimiter.start()
                self.skip_lf = self.pending[pos:pos + 1] == b"\r"
                line, self.pending = self.pending[:pos], self.pending[pos + 1:]
                if self.first_line:
                    line = line.removeprefix(b"\xef\xbb\xbf")
                    self.first_line = False
                if not line:
                    event, data = self.event, self.data
                    self.event, self.data = "message", []
                    if data:
                        try:
                            return event, b"\n".join(data).decode("utf-8")
                        except UnicodeError as exc:
                            raise SessionError("Invalid SSE UTF-8") from exc
                elif line.startswith(b"data:") or line == b"data":
                    self.data.append(line[5:].removeprefix(b" "))
                elif line.startswith(b"event:"):
                    try:
                        self.event = line[6:].removeprefix(b" ").decode("utf-8") or "message"
                    except UnicodeError as exc:
                        raise SessionError("Invalid SSE event type") from exc
                continue
            if self.eof:
                raise SessionError("SSE stream closed before the expected event")
            try:
                chunk = next(self.chunks)
            except StopIteration:
                self.eof = True
                continue
            self.size += len(chunk)
            if self.size > self.max_bytes:
                raise SessionError("Response exceeds size limit")
            self.pending += chunk


class StreamableHttpSession:
    SUPPORTED = ("2025-06-18", "2025-03-26")
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, client, url, timeout=12.0, trace=None):
        self.client, self.url, self.timeout, self.trace = client, url, timeout, trace
        self.ready = False
        self.secrets = set()
        self.initialize_status = None
        self.capabilities = {}
        self._next_id = 1000  # Keep intentional scanner probe IDs separate.
        client.headers["Accept"] = "application/json, text/event-stream"
        client.headers.pop("Mcp-Session-Id", None)
        client.headers["MCP-Protocol-Version"] = self.SUPPORTED[0]

    def _record(self, **entry):
        if self.trace is not None:
            self.trace.append(dict(transport="http", url=self.url, **entry))

    def exchange(self, payload):
        """Raw exchange for deliberately invalid scanner probes as well as RPC."""
        deadline = time.monotonic() + self.timeout
        self._record(direction="send", request=payload)
        with self.client.stream("POST", self.url, json=payload, timeout=self.timeout) as response:
            status = response.status_code
            if payload.get("method") == "initialize" and payload.get("id") == 0:
                self.initialize_status = status
            self._record(direction="recv", status=status)
            if "id" not in payload:
                if status != 202:
                    raise SessionError(f"Notification was not accepted (HTTP {status})")
                return status, None
            if not 200 <= status < 300:
                return status, self._error_body(response, deadline)
            sid = response.headers.get("Mcp-Session-Id")
            if sid is not None and payload.get("id") == 0:
                if not sid or any(ord(c) < 33 or ord(c) > 126 for c in sid):
                    raise SessionError("Invalid MCP session identifier")
                self.secrets.add(sid)
                self.client.headers["Mcp-Session-Id"] = sid
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type == "text/event-stream":
                reader = SSEReader(response, self.MAX_BYTES)
                while True:
                    event, data = reader.next_event(deadline)
                    if event != "message":
                        continue
                    message = self._decode(data)
                    if self._matches(message, payload["id"], deadline):
                        return status, message
            if content_type != "application/json":
                raise SessionError(f"Unsupported response content type: {content_type}")
            body = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() >= deadline:
                    raise SessionError("Response deadline exceeded")
                body.extend(chunk)
                if len(body) > self.MAX_BYTES:
                    raise SessionError("Response exceeds size limit")
            message = self._decode(body)
            if self._matches(message, payload["id"], deadline):
                return status, message
            raise SessionError("No matching JSON-RPC response received")

    def _error_body(self, response, deadline):
        """Retain bounded HTTP diagnostics; never consume an endless error stream."""
        body = bytearray()
        limit = 16 * 1024
        truncated = False
        try:
            for chunk in response.iter_bytes():
                if time.monotonic() >= deadline:
                    truncated = True
                    break
                room = limit - len(body)
                body.extend(chunk[:room])
                if len(chunk) >= room:
                    truncated = True
                    break
        except Exception as exc:
            return {"error": {"message": f"HTTP {response.status_code}; error body unavailable: {type(exc).__name__}"}}
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeError):
            parsed = {"message": body.decode("utf-8", errors="replace") or f"HTTP {response.status_code}"}
        error = parsed.get("error", parsed) if isinstance(parsed, dict) else parsed
        data = {"error": error}
        if truncated:
            data["diagnostic_truncated"] = True
        # Sanitize before diagnostics cross the session boundary.
        return self._sanitize(data)

    def _sanitize(self, value):
        if isinstance(value, str):
            return redact_secrets(value, self.secrets)
        if isinstance(value, dict):
            return {k: self._sanitize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize(v) for v in value]
        return value

    def close(self):
        self.ready = False

    @staticmethod
    def _decode(data):
        try:
            return json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise SessionError("Malformed JSON response") from exc

    def _matches(self, message, request_id, deadline):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise SessionError("Invalid JSON-RPC response")
        if "method" in message:
            if "id" in message:
                # Only ping is implemented; no sampling/roots capabilities advertised.
                reply = {"jsonrpc": "2.0", "id": message["id"]}
                if message["method"] == "ping":
                    reply["result"] = {}
                else:
                    reply["error"] = {"code": -32601, "message": "Method not supported"}
                self._send_server_response(reply, deadline)
            return False
        if type(message.get("id")) is not type(request_id) or message.get("id") != request_id:
            return False
        if ("result" in message) == ("error" in message):
            raise SessionError("Response must contain exactly one result or error")
        self._record(direction="recv", response=message)
        return True

    def _send_server_response(self, reply, deadline):
        with self.client.stream("POST", self.url, json=reply,
                                timeout=max(0.001, deadline - time.monotonic())) as response:
            if response.status_code != 202:
                raise SessionError("Server did not accept client response")

    def initialize(self):
        self.ready = False
        try:
            client_version = version("mcp-security-scanner")
        except PackageNotFoundError:
            client_version = "unknown"
        status, data = self.exchange({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": self.SUPPORTED[0], "capabilities": {},
            "clientInfo": {"name": "mcp-security-scanner", "version": client_version},
        }})
        result = data.get("result")
        if not isinstance(result, dict):
            raise SessionError(f"Initialization failed (HTTP {status}): {data}")
        negotiated = result.get("protocolVersion")
        if negotiated not in self.SUPPORTED:
            raise SessionError("Unsupported or missing negotiated protocol version")
        info = result.get("serverInfo")
        if not isinstance(info, dict) or not all(isinstance(info.get(k), str) for k in ("name", "version")):
            raise SessionError("Missing or malformed serverInfo")
        if not isinstance(result.get("capabilities"), dict):
            raise SessionError("Missing or malformed capabilities")
        self.capabilities = result["capabilities"]
        self.client.headers["MCP-Protocol-Version"] = negotiated
        self.exchange({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.ready = True
        return status, data

    def call(self, method, params):
        if not self.ready:
            raise SessionError("Session is not initialized")
        request_id = self._next_id
        self._next_id += 1
        return self.exchange({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
