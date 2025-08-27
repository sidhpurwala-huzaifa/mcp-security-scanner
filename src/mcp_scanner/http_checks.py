from __future__ import annotations

from typing import Dict, List

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


def scan_http_base(base_url: str, spec_index: Dict[str, SpecCheck]) -> List[Finding]:
    findings: List[Finding] = []
    client = httpx.Client(follow_redirects=True, timeout=5.0)

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
            r_ok = client.get(sse_url)
            exists = r_ok.status_code < 500
            # Now try forged Origin
            r = client.get(sse_url, headers={"Origin": "http://evil.tld"})
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
            r = client.get(sse_url)
            reachable = r.status_code < 500
            findings.append(_finding(kf03, passed=not reachable, details=f"status={r.status_code}"))
        except Exception as e:  # noqa: BLE001
            findings.append(_finding(kf03, passed=True, details=f"error={type(e).__name__}:{e}"))

    client.close()
    return findings


