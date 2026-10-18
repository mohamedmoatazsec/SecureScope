"""SARIF 2.1.0 output, for GitHub code scanning and any other SARIF consumer.

Each finding ID becomes a rule; each finding becomes a result whose
location is the scanned URL. GitHub's `security-severity` property is
set so findings are bucketed the same way as code-scanning alerts.
"""

from __future__ import annotations

import json
from typing import Any

from securescope import __version__
from securescope.findings import Finding, Severity
from securescope.scanner import Report

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub maps security-severity scores onto critical/high/medium/low buckets.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security", finding.check]
    if finding.cwe:
        tags.append(f"external/cwe/cwe-{finding.cwe}")
    return {
        "id": finding.id,
        "name": finding.id.title().replace("-", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {
            "text": finding.remediation,
            "markdown": f"**Remediation**\n\n{finding.remediation}\n\n"
            + "\n".join(f"- {ref}" for ref in finding.references),
        },
        "helpUri": finding.references[0]
        if finding.references
        else "https://github.com/mohamedmoatazsec/SecureScope",
        "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
        "properties": {
            "tags": tags,
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "precision": {"certain": "very-high", "firm": "high", "tentative": "medium"}[
                finding.confidence.value
            ],
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}. {finding.description}"},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": finding.target}},
                "logicalLocations": [
                    {"name": str(finding.evidence.get("name", finding.check)), "kind": "resource"}
                ],
            }
        ],
        "partialFingerprints": {"securescope/v1": finding.fingerprint()},
        "properties": {
            "evidence": finding.evidence,
            "check": finding.check,
            "severity": finding.severity.value,
        },
    }


def build_sarif(report: Report) -> dict[str, Any]:
    findings = report.findings
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rules.setdefault(finding.id, _rule(finding))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureScope",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/mohamedmoatazsec/SecureScope",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": True, "endTimeUtc": report.generated}],
                "results": [_result(f) for f in findings],
                "properties": {"targets": [t.target for t in report.targets]},
            }
        ],
    }


def render_sarif(report: Report) -> str:
    return json.dumps(build_sarif(report), indent=2) + "\n"
