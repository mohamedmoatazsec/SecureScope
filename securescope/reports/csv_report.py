"""CSV report: one row per finding, for spreadsheets and ticketing imports."""

from __future__ import annotations

import csv
import io
import json

from securescope.scanner import Report

COLUMNS = [
    "target",
    "severity",
    "id",
    "title",
    "check",
    "confidence",
    "cwe",
    "evidence",
    "remediation",
    "references",
    "fingerprint",
]


def render_csv(report: Report) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for finding in report.findings:
        writer.writerow(
            [
                finding.target,
                finding.severity.value,
                finding.id,
                finding.title,
                finding.check,
                finding.confidence.value,
                finding.cwe or "",
                json.dumps(finding.evidence, ensure_ascii=False, sort_keys=True),
                finding.remediation,
                " ".join(finding.references),
                finding.fingerprint(),
            ]
        )
    return buffer.getvalue()
