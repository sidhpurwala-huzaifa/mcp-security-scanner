from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator, computed_field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Outcome(str, Enum):
    passed = "pass"
    failed = "fail"
    error = "error"
    skipped = "skipped"


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    status: Outcome
    passed: Optional[bool] = None
    details: str = ""
    remediation: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_outcome(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "status" not in data:
            if not isinstance(data.get("passed"), bool):
                raise ValueError("A finding requires status or a boolean passed value")
            data["status"] = Outcome.passed if data["passed"] else Outcome.failed
        status = Outcome(data["status"])
        expected = {Outcome.passed: True, Outcome.failed: False}.get(status)
        if "passed" in data and data["passed"] is not expected:
            raise ValueError("passed must agree with status; error/skipped require null")
        data["passed"] = expected
        return data


class Report(BaseModel):
    schema_version: int = 2
    target: str
    started_at: datetime
    finished_at: datetime
    findings: List[Finding]

    @computed_field
    @property
    def summary(self) -> Dict[str, int]:
        totals: Dict[str, int] = {s.value: 0 for s in Severity}
        totals["passed"] = 0
        totals["failed"] = 0
        totals["errors"] = 0
        totals["skipped"] = 0
        for f in self.findings:
            if f.status == Outcome.passed:
                totals["passed"] += 1
            elif f.status == Outcome.failed:
                totals["failed"] += 1
                totals[f.severity.value] += 1
            elif f.status == Outcome.error:
                totals["errors"] += 1
            else:
                totals["skipped"] += 1
        return totals

    @property
    def exit_code(self) -> int:
        if self.summary["errors"]:
            return 2
        if self.summary["failed"]:
            return 1
        return 0

    @classmethod
    def new(cls, target: str, findings: List[Finding]) -> "Report":
        now = datetime.now(timezone.utc)
        return cls(target=target, started_at=now, finished_at=now, findings=findings)
