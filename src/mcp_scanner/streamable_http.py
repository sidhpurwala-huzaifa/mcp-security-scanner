"""Synchronous Streamable HTTP lifecycle and correlated JSON/SSE exchanges.

Legacy GET/endpoint-event transport deliberately lives outside this module.
Requests are never replayed: a lost response may follow a completed tool call.
"""
import json
import re
import time
from importlib.metadata import PackageNotFoundError, version


class SessionError(RuntimeError):
    pass


class StreamableHttpSession:
    SUPPORTED = ("2025-06-18", "2025-03-26")
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, client, url, timeout=12.0, trace=None):
        self.client, self.url, self.timeout, self.trace = client, url, timeout, trace
        self.ready = False
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
                return status, {"error": f"HTTP {status}"}
            sid = response.headers.get("Mcp-Session-Id")
            if sid is not None and payload.get("id") == 0:
                if not sid or any(ord(c) < 33 or ord(c) > 126 for c in sid):
                    raise SessionError("Invalid MCP session identifier")
                self.client.headers["Mcp-Session-Id"] = sid
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            chunks = response.iter_bytes()
            size = 0
            pending = b""
            first_line = True
            data_lines = []
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SessionError("Response deadline exceeded")
                try:
                    chunk = next(chunks)
                except StopIteration:
                    break
                if time.monotonic() >= deadline:
                    raise SessionError("Response deadline exceeded")
                size += len(chunk)
                if size > self.MAX_BYTES:
                    raise SessionError("Response exceeds size limit")
                pending += chunk
                if content_type == "text/event-stream":
                    while True:
                        delimiter = re.search(b"[\\r\\n]", pending)
                        if delimiter is None:
                            break
                        pos = delimiter.start()
                        if pending[pos:] == b"\r":
                            break  # CRLF may be split across network chunks.
                        length = 2 if pending[pos:pos + 2] == b"\r\n" else 1
                        line, pending = pending[:pos], pending[pos + length:]
                        if first_line:
                            line = line.removeprefix(b"\xef\xbb\xbf")
                            first_line = False
                        if not line:
                            if data_lines:
                                message = self._decode(b"\n".join(data_lines))
                                data_lines = []
                                if self._matches(message, payload["id"], deadline):
                                    return status, message
                        elif line.startswith(b"data:"):
                            data_lines.append(line[5:].removeprefix(b" "))
            if content_type == "application/json":
                message = self._decode(pending)
                if self._matches(message, payload["id"], deadline):
                    return status, message
            elif content_type != "text/event-stream":
                raise SessionError(f"Unsupported response content type: {content_type}")
            raise SessionError("No matching JSON-RPC response received")

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
                with self.client.stream("POST", self.url, json=reply, timeout=max(0.001, deadline - time.monotonic())) as response:
                    if response.status_code != 202:
                        raise SessionError("Server did not accept client response")
            return False
        if type(message.get("id")) is not type(request_id) or message.get("id") != request_id:
            return False
        if ("result" in message) == ("error" in message):
            raise SessionError("Response must contain exactly one result or error")
        self._record(direction="recv", response=message)
        return True

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
