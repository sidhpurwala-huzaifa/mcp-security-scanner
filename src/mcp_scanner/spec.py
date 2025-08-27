from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


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
        # Extract JSON from fenced code block
        parts = stripped.split("```")
        if len(parts) >= 3:
            block = parts[1]
            # Drop optional language tag like "json" on first line
            if "\n" in block:
                first, rest = block.split("\n", 1)
                if first.strip().lower() in {"json", "jsonc"}:
                    block = rest
            stripped = block.strip()
    return json.loads(stripped)


def load_spec(spec_path: Path) -> Dict[str, SpecCheck]:
    raw = _load_json_text(spec_path.read_text())
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


