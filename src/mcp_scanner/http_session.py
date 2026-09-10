"""Explicit transport selection and the legacy HTTP+SSE session lifecycle."""
import time
from urllib.parse import urljoin, urlsplit, parse_qs

import httpx

from .streamable_http import SSEReader, SessionError, StreamableHttpSession


def same_origin_endpoint(base, endpoint):
    """Do not send credentials to a server-selected foreign origin."""
    target = urljoin(base, endpoint)
    try:
        source, dest = urlsplit(base), urlsplit(target)
        def origin(url):
            return url.scheme.lower(), url.hostname, url.port or (443 if url.scheme == "https" else 80)
        if (dest.scheme not in ("http", "https") or not dest.hostname
                or dest.username is not None or dest.password is not None
                or dest.fragment or origin(source) != origin(dest)):
            raise ValueError("unsafe endpoint")
    except ValueError as exc:
        raise SessionError("Legacy endpoint must be an HTTP URL on the original origin without credentials or fragment") from exc
    return target


class LegacySseSession(StreamableHttpSession):
    SUPPORTED = ("2024-11-05", "2025-03-26", "2025-06-18")

    def __init__(self, client, url, timeout=12.0, trace=None):
        super().__init__(client, url, timeout, trace)
        self.sse_url = url
        self._context = None
        self._reader = None
        self.handshake_status = None
        # Legacy sessions are identified by the advertised endpoint, not a
        # fabricated session header extracted from arbitrary query text.
        client.headers.pop("MCP-Protocol-Version", None)

    def initialize(self):
        deadline = time.monotonic() + self.timeout
        try:
            self._record(direction="send", method="GET")
            self._context = self.client.stream(
                "GET", self.sse_url, headers={"Accept": "text/event-stream"},
                timeout=self.timeout, follow_redirects=False,
            )
            response = self._context.__enter__()
            self.handshake_status = response.status_code
            self._record(direction="recv", status=response.status_code)
            if response.status_code != 200:
                raise SessionError(f"Legacy handshake failed (HTTP {response.status_code})")
            if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/event-stream":
                raise SessionError("Legacy handshake did not return text/event-stream")
            self._reader = SSEReader(response, self.MAX_BYTES)
            while True:
                event, data = self._reader.next_event(deadline)
                if event == "endpoint":
                    if not data.strip() or any(c.isspace() or ord(c) < 32 for c in data):
                        raise SessionError("Malformed legacy endpoint event")
                    self.url = same_origin_endpoint(self.sse_url, data)
                    for key, values in parse_qs(urlsplit(self.url).query).items():
                        if key.lower() in ("sessionid", "session_id", "token", "access_token"):
                            self.secrets.update(values)
                    break
            return super().initialize()
        except Exception:
            self.close()
            raise

    def _post(self, payload, deadline):
        self._record(direction="send", request=payload)
        headers = httpx.Headers(self.client.headers)
        headers["Accept"] = "application/json, text/event-stream"
        with self.client.stream("POST", self.url, json=payload, headers=headers,
                                timeout=max(0.001, deadline - time.monotonic()),
                                follow_redirects=False) as response:
            self._record(direction="recv", status=response.status_code)
            self._last_post_error = self._error_body(response, deadline) if not 200 <= response.status_code < 300 else None
            return response.status_code

    def exchange(self, payload):
        if self._reader is None:
            raise SessionError("Legacy SSE connection is not open")
        deadline = time.monotonic() + self.timeout
        try:
            status = self._post(payload, deadline)
            if payload.get("method") == "initialize" and payload.get("id") == 0:
                self.initialize_status = status
            if not 200 <= status < 300:
                if "id" not in payload:
                    raise SessionError(f"Notification was not accepted (HTTP {status})")
                return status, self._last_post_error
            if "id" not in payload:
                return status, None
            while True:
                event, data = self._reader.next_event(deadline)
                if event == "endpoint":
                    # Never rotate endpoints and replay a possibly executed call.
                    raise SessionError("Legacy endpoint changed during a request; start a new session")
                if event == "message":
                    message = self._decode(data)
                    if self._matches(message, payload["id"], deadline):
                        return status, message
        except Exception:
            self.close()
            raise

    def _send_server_response(self, reply, deadline):
        if not 200 <= self._post(reply, deadline) < 300:
            raise SessionError("Server did not accept client response")

    def close(self):
        super().close()
        context, self._context = self._context, None
        self._reader = None
        if context is not None:
            context.__exit__(None, None, None)


class HttpSession:
    """Select once at initialization; never fall back after normal RPC begins."""
    def __init__(self, client, url, timeout=12.0, trace=None, transport="auto", sse_endpoint=None, secrets=None):
        if transport not in ("auto", "http", "sse"):
            raise ValueError("Unsupported HTTP transport")
        self.secrets = secrets if secrets is not None else set()
        self.client, self.base_url = client, url
        self.timeout, self.trace, self.mode = timeout, trace, transport
        self.sse_url = same_origin_endpoint(url, sse_endpoint) if sse_endpoint else url
        self.transport = "sse" if transport == "sse" else "http"
        cls = LegacySseSession if transport == "sse" else StreamableHttpSession
        self.active = cls(client, self.sse_url if transport == "sse" else url, timeout, trace)
        self.active.secrets = self.secrets

    @property
    def url(self):
        return self.active.url

    @property
    def initialize_status(self):
        return self.active.initialize_status

    def initialize(self):
        try:
            return self.active.initialize()
        except SessionError:
            # 404/405 indicate an unavailable POST endpoint. Authentication,
            # malformed responses, and JSON-RPC errors must remain visible.
            if self.mode != "auto" or self.active.initialize_status not in (404, 405):
                raise
            self.active.close()
            self.active = LegacySseSession(self.client, self.sse_url, self.timeout, self.trace)
            self.active.secrets = self.secrets
            self.transport = "sse"
            return self.active.initialize()

    def call(self, method, params):
        return self.active.call(method, params)

    def exchange(self, payload):
        return self.active.exchange(payload)

    def close(self):
        self.active.close()
