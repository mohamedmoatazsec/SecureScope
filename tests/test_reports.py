import csv
import io
import json

from securescope.diff import diff_findings, new_findings
from securescope.findings import CheckResult, Finding, Severity
from securescope.reports import FORMATS, render, write
from securescope.reports.sarif_report import build_sarif
from securescope.scanner import Report, ScanResult

HOSTILE = "</td><script>alert(1)</script><img src=x onerror=alert(2)>"


def make_report(diff=False):
    finding = Finding(
        id="SERVER-VERSION-DISCLOSED",
        title=f"Server header reveals the software version ({HOSTILE})",
        severity=Severity.LOW,
        description="desc",
        remediation="fix",
        check="disclosure",
        evidence={"name": "Server", "value": HOSTILE},
        references=["https://example.test/ref", "javascript:alert(1)"],
        cwe=200,
        target="https://target.test/",
    )
    high = Finding(
        id="HSTS-MISSING",
        title="No Strict-Transport-Security header",
        severity=Severity.HIGH,
        description="d",
        remediation="r",
        check="headers",
        evidence={"name": "Strict-Transport-Security", "value": None},
        target="https://target.test/",
    )
    checks = [
        CheckResult(
            id="disclosure", name="Information disclosure", findings=[finding], facts={"server": HOSTILE}
        ),
        CheckResult(id="headers", name="Security headers", findings=[high]),
        CheckResult(id="tls", name="TLS and transport", error=f"boom {HOSTILE}"),
        CheckResult(id="ports", name="Open ports", skipped="pass --ports to enable"),
    ]
    result = ScanResult(
        target="https://target.test/",
        started="2026-10-18T00:00:00Z",
        duration=1.5,
        reachable=True,
        checks=checks,
    )
    report = Report(targets=[result], generated="2026-10-18T00:00:01Z")
    if diff:
        report.diff = diff_findings(report.findings, [finding])
    return report


def test_every_format_renders():
    report = make_report(diff=True)
    for fmt in FORMATS:
        assert render(report, fmt)


def test_json_shape_and_ordering():
    data = json.loads(render(make_report(), "json"))
    assert data["tool"] == "SecureScope"
    assert data["summary"]["grade"] == "C"  # one high (-20) + one low (-4) = 76
    target = data["targets"][0]
    assert [f["id"] for f in target["findings"]] == ["HSTS-MISSING", "SERVER-VERSION-DISCLOSED"]
    assert {c["id"]: c["status"] for c in target["checks"]} == {
        "disclosure": "ok",
        "headers": "ok",
        "tls": "error",
        "ports": "skipped",
    }
    assert target["findings"][0]["fingerprint"]


def test_html_escapes_everything_from_the_target():
    html = render(make_report(), "html")
    assert html.count("<script") == 1  # only the report's own filter script
    assert "<script>alert" not in html
    assert "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'href="javascript:' not in html  # only https references become links
    assert "SecureScope" in html and "target.test" in html


def test_markdown_mentions_grade_and_diff():
    md = render(make_report(diff=True), "md")
    assert "**Grade C**" in md
    assert "HSTS-MISSING" in md
    assert "1 new, 0 fixed, 1 unchanged" in md


def test_sarif_structure():
    sarif = build_sarif(make_report())
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert {r["ruleId"] for r in run["results"]} <= set(rule_ids)
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["HSTS-MISSING"] == "error" and levels["SERVER-VERSION-DISCLOSED"] == "note"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "https://target.test/"
    )
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "SERVER-VERSION-DISCLOSED")
    assert "external/cwe/cwe-200" in rule["properties"]["tags"]
    assert rule["properties"]["security-severity"] == "3.0"


def test_csv_rows():
    rows = list(csv.reader(io.StringIO(render(make_report(), "csv"))))
    assert rows[0][:4] == ["target", "severity", "id", "title"]
    assert len(rows) == 3
    assert rows[1][2] == "HSTS-MISSING"


def test_write_creates_files(tmp_path):
    report = make_report()
    for fmt in FORMATS:
        path = write(report, fmt, str(tmp_path / "out"), "scan")
        assert path.exists() and path.stat().st_size > 0
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [
        "scan.csv",
        "scan.html",
        "scan.json",
        "scan.md",
        "scan.sarif",
    ]


def test_diff_new_fixed_unchanged():
    report = make_report()
    current = report.findings
    baseline = [current[1]]  # only the LOW existed before
    diff = diff_findings(current, baseline)
    assert diff["counts"] == {"new": 1, "fixed": 0, "unchanged": 1}
    assert diff["new"][0]["id"] == "HSTS-MISSING"
    assert [f.id for f in new_findings(current, baseline)] == ["HSTS-MISSING"]

    fixed = diff_findings([], current)
    assert fixed["counts"]["fixed"] == 2 and fixed["counts"]["new"] == 0
