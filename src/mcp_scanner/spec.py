from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from importlib.resources import files as pkg_files
except Exception:  # pragma: no cover
    pkg_files = None  # type: ignore


@dataclass
class SpecCheck:
    id: str
    title: str
    category: str
    severity: str
    applies_to: List[str]
    remediation: List[str]
    references: List[str]


def _load_json_text(text: str) -> dict:
    stripped = text.strip()
    if stripped.startswith("```"):
        # Extract JSON from fenced code block (tolerate variants like ````json`)
        parts = stripped.split("```")
        if len(parts) >= 2:
            block = parts[1]
            if "\n" in block:
                first, rest = block.split("\n", 1)
                lang = first.strip().strip("`").lower()
                if lang.startswith("json"):
                    block = rest
            stripped = block.strip()
    return json.loads(stripped)


def load_spec(spec_path: Optional[Path] = None) -> Dict[str, SpecCheck]:
    text: str
    if spec_path is not None:
        text = spec_path.read_text()
    else:
        # Load from packaged resource
        if pkg_files is None:
            raise RuntimeError("importlib.resources unavailable and no spec_path provided")
        res = pkg_files(__package__) / "scanner_specs.schema"
        text = res.read_text(encoding="utf-8")
    raw = _load_json_text(text)
    checks: Dict[str, SpecCheck] = {}
    for c in raw.get("checks", []):
        checks[c["id"]] = SpecCheck(
            id=c["id"],
            title=c["title"],
            category=c["category"],
            severity=c["severity"],
            applies_to=c["applies_to"],
            remediation=c.get("remediation", []),
            references=c.get("references", []),
        )
    return checks


