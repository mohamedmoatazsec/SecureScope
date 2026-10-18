"""The finding model: what every check produces and every report consumes.

A finding is one concrete, evidence-backed issue on one target. Checks
never print; they return findings and facts, and the reporters decide how
to present them. Keeping the model small and serialisable is what makes
JSON, SARIF, Markdown and baseline diffs cheap to add.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Lower is more severe; handy for sorting and threshold checks."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from exc


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(str, Enum):
    """How sure the check is that the finding is real.

    CERTAIN: observed directly (a header is missing, a flag is absent).
    FIRM: inferred from strong evidence (a version string, a reflected origin).
    TENTATIVE: heuristic; verify by hand before reporting it to anyone.
    """

    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    check: str
    confidence: Confidence = Confidence.CERTAIN
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    cwe: int | None = None
    target: str = ""

    def fingerprint(self) -> str:
        """Stable identity used by baseline diffs: same issue, same place."""
        key = "|".join(
            [self.id, self.target]
            + [str(self.evidence.get(k, "")) for k in ("name", "directive", "location", "ip")]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint(),
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "check": self.check,
            "target": self.target,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": dict(self.evidence),
            "references": list(self.references),
            "cwe": self.cwe,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            id=data["id"],
            title=data.get("title", data["id"]),
            severity=Severity.parse(data.get("severity", "info")),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            check=data.get("check", ""),
            confidence=Confidence(data.get("confidence", "certain")),
            evidence=dict(data.get("evidence") or {}),
            references=list(data.get("references") or []),
            cwe=data.get("cwe"),
            target=data.get("target", ""),
        )


@dataclass
class CheckResult:
    """Everything one check learned about one target."""

    id: str
    name: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    skipped: str | None = None  # reason, when the check did not run

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        if self.error:
            return "error"
        return "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "error": self.error,
            "skipped": self.skipped,
            "findings": [f.to_dict() for f in self.findings],
            "facts": self.facts,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by check and id so output is deterministic."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.check, f.id, str(f.evidence.get("name", ""))))


def meets_threshold(finding: Finding, threshold: Severity) -> bool:
    """True when `finding` is at least as severe as `threshold`."""
    return finding.severity.rank <= threshold.rank
