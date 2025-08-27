from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    passed: bool
    details: str = ""
    remediation: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class Report(BaseModel):
    target: str
    started_at: datetime
    finished_at: datetime
    findings: List[Finding]

    @property
    def summary(self) -> Dict[str, int]:
        totals: Dict[str, int] = {s.value: 0 for s in Severity}
        totals["passed"] = 0
        totals["failed"] = 0
        for f in self.findings:
            if f.passed:
                totals["passed"] += 1
            else:
                totals["failed"] += 1
                totals[f.severity.value] += 1
        return totals

    @classmethod
    def new(cls, target: str, findings: List[Finding]) -> "Report":
        now = datetime.now(timezone.utc)
        return cls(target=target, started_at=now, finished_at=now, findings=findings)


