"""Compare a scan against a baseline report so CI can fail only on regressions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securescope.findings import Finding, sort_findings


def load_baseline(path: str) -> list[Finding]:
    """Read the findings out of a JSON report written by an earlier run."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("tool") != "SecureScope":
        raise ValueError(f"baseline {path} is not a SecureScope JSON report")
    findings: list[Finding] = []
    for target in data.get("targets", []):
        for raw in target.get("findings", []):
            try:
                findings.append(Finding.from_dict(raw))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"baseline {path} has a malformed finding: {exc}") from exc
    return findings


def diff_findings(current: list[Finding], baseline: list[Finding]) -> dict[str, Any]:
    """Split `current` into new / unchanged relative to `baseline`, and list what was fixed."""
    before = {f.fingerprint(): f for f in baseline}
    after = {f.fingerprint(): f for f in current}

    new = sort_findings([f for key, f in after.items() if key not in before])
    fixed = sort_findings([f for key, f in before.items() if key not in after])
    unchanged = sort_findings([f for key, f in after.items() if key in before])

    return {
        "new": [f.to_dict() for f in new],
        "fixed": [f.to_dict() for f in fixed],
        "unchanged": len(unchanged),
        "counts": {"new": len(new), "fixed": len(fixed), "unchanged": len(unchanged)},
    }


def new_findings(current: list[Finding], baseline: list[Finding]) -> list[Finding]:
    before = {f.fingerprint() for f in baseline}
    return sort_findings([f for f in current if f.fingerprint() not in before])
