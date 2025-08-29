from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, Report, Severity
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


class StdioClient:
    def __init__(self, cmd: str) -> None:
        args = shlex.split(cmd)
        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def send_recv(self, method: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("stdio pipes not available")
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        line = json.dumps(req) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        resp_line = self.proc.stdout.readline()
        try:
            return json.loads(resp_line)
        except json.JSONDecodeError:
            return {"error": "non-json", "raw": resp_line}

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
        finally:
            self.proc.terminate()


def run_checks_stdio(cmd: str, spec_index: Dict[str, SpecCheck]) -> List[Finding]:
    findings: List[Finding] = []
    client = StdioClient(cmd)

    try:
        base = spec_index.get("BASE-01")
        if base:
            resp = client.send_recv("initialize", {})
            ok = isinstance(resp, dict) and "result" in resp and "capabilities" in resp.get("result", {})
            findings.append(_finding(base, ok, json.dumps(resp)))

        tools_list = client.send_recv("tools/list", {})
        tools = tools_list.get("result", {}).get("tools", []) if isinstance(tools_list, dict) else []

        a01 = spec_index.get("A-01")
        if a01:
            findings.append(_finding(a01, passed=(not bool(tools)), details=json.dumps(tools_list)))

        r01 = spec_index.get("R-01")
        if r01:
            attempt = client.send_recv("resources/read", {"uri": "file:///../../etc/hosts"})
            accepted = "result" in attempt and isinstance(attempt.get("result"), dict)
            findings.append(_finding(r01, passed=not accepted, details=json.dumps(attempt)))

        # Minimal R-03 via stdio
        r03 = spec_index.get("R-03")
        if r03:
            res_list = client.send_recv("resources/list", {})
            resources = res_list.get("result", {}).get("resources", []) if isinstance(res_list, dict) else []
            sensitive_keywords = ["credential", "secret", "token", "key", "password"]
            suspects = []
            for r in resources:
                name = (r.get("name") or "").lower()
                uri_r = (r.get("uri") or "").lower()
                if any(k in name or k in uri_r for k in sensitive_keywords):
                    suspects.append(r)
            findings.append(_finding(r03, passed=len(suspects) == 0, details=json.dumps(suspects)))
    finally:
        client.close()

    return findings


def scan_stdio(cmd: str, spec_index: Dict[str, SpecCheck]) -> Report:
    findings = run_checks_stdio(cmd, spec_index)
    return Report.new(target=f"stdio:{cmd}", findings=findings)


