"""Turn a list of findings into a 0-100 score and a letter grade.

The scheme is deliberately simple so a grade is explainable in one
sentence: start at 100, subtract a fixed amount per finding by severity,
floor at 0. Informational findings never cost points.
"""

from __future__ import annotations

from securescope.findings import Finding, Severity

PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}

GRADES = [
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (0, "F"),
]


def score(findings: list[Finding]) -> int:
    total = 100
    for finding in findings:
        total -= PENALTY[finding.severity]
    return max(0, total)


def grade(value: int) -> str:
    for threshold, letter in GRADES:
        if value >= threshold:
            return letter
    return "F"


def summarize(findings: list[Finding]) -> dict:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    value = score(findings)
    return {"score": value, "grade": grade(value), "counts": counts, "total": len(findings)}
