"""Keep transport failure separate from evidence produced by an active probe."""
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ProbeOutcome:
    http_status: Optional[int]
    data: Any = None
    transport_error: Optional[str] = None

    def problem(self, *, denied_statuses=(), denied_rpc_codes=()):
        if self.transport_error:
            return self.transport_error
        status = self.http_status
        if status in denied_statuses:
            return None
        if status is None or not 200 <= status < 300:
            return f"HTTP {status}; {self.data}"
        if not isinstance(self.data, dict):
            return f"HTTP {status}; malformed RPC response"
        error = self.data.get("error")
        if error is not None:
            if (isinstance(error, dict) and type(error.get("code")) is int
                    and error["code"] in denied_rpc_codes and isinstance(error.get("message"), str)):
                return None
            return f"HTTP {status}; unexpected JSON-RPC error: {error}"
        result = self.data.get("result")
        if not isinstance(result, dict):
            return f"HTTP {status}; missing or invalid RPC result"
        if result.get("isError") is True:
            return f"HTTP {status}; tool execution failed: {result}"
        return None
