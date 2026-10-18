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


FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: object) -> str:
    """Stop spreadsheet formula injection.

    A target that answers with `Server: =HYPERLINK(...)` or `-2+3+cmd|' /C calc'!A0` would
    otherwise become a live formula when the CSV is opened in Excel or LibreOffice. Prefixing
    a single quote makes the cell literal text (the standard OWASP mitigation).
    """
    text = str(value)
    if text and text[0] in FORMULA_TRIGGERS:
        return "'" + text
    return text


def render_csv(report: Report) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for finding in report.findings:
        writer.writerow(
            [
                neutralize(cell)
                for cell in (
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
                )
            ]
        )
    return buffer.getvalue()
