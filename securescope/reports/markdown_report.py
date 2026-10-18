"""Markdown report: readable in a pull request comment or a GitHub job summary."""

from __future__ import annotations

from securescope.findings import Finding, Severity
from securescope.scanner import Report, ScanResult

BADGE = {
    Severity.CRITICAL: "🟥 Critical",
    Severity.HIGH: "🟧 High",
    Severity.MEDIUM: "🟨 Medium",
    Severity.LOW: "🟦 Low",
    Severity.INFO: "⬜ Info",
}


def _escape(text: str) -> str:
    """Neutralise Markdown/HTML from target-derived text.

    Job summaries and PR comments render Markdown, and GitHub-flavoured Markdown allows raw
    HTML, so `<img>` or `<a>` tags in a header value would otherwise render. Backticks are
    replaced so a value cannot break out of the code spans the report wraps evidence in.
    """
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "'")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _code(text: str) -> str:
    """Wrap target-derived text in a Markdown code span it cannot break out of."""
    cleaned = str(text).replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return f"`{cleaned}`"


def _evidence_line(finding: Finding) -> str:
    parts = []
    for key, value in finding.evidence.items():
        if value in (None, "", [], {}):
            continue
        if key == "value" and finding.evidence.get("directive"):
            continue  # the directive names the problem; the full policy is in the JSON/HTML reports
        text = str(value)
        if len(text) > 120:
            text = text[:119] + "…"
        parts.append(_code(f"{key}={text}"))
    return ", ".join(parts)


def render_target(result: ScanResult) -> str:
    summary = result.summary
    lines = [f"## {_escape(result.target)}", ""]
    if not result.reachable:
        lines.append(f"> ⚠️ Target could not be fetched: {_escape(result.error)}")
        lines.append("")
    counts = summary["counts"]
    lines.append(
        f"**Grade {summary['grade']}** (score {summary['score']}/100) · "
        f"{counts['critical']} critical · {counts['high']} high · {counts['medium']} medium · "
        f"{counts['low']} low · {counts['info']} info"
    )
    lines.append("")

    findings = [f for f in result.findings if f.severity != Severity.INFO]
    if findings:
        lines.append("| Severity | Finding | Evidence |")
        lines.append("|---|---|---|")
        for finding in findings:
            lines.append(
                f"| {BADGE[finding.severity]} | **{_escape(finding.title)}** (`{finding.id}`) | "
                f"{_evidence_line(finding)} |"
            )
        lines.append("")
        lines.append("<details><summary>Remediation</summary>")
        lines.append("")
        for finding in findings:
            lines.append(f"- **{_escape(finding.title)}** — {_escape(finding.remediation)}")
        lines.append("")
        lines.append("</details>")
    else:
        lines.append("No findings above informational level.")

    info = [f for f in result.findings if f.severity == Severity.INFO]
    if info:
        lines.append("")
        lines.append(f"<details><summary>{len(info)} informational</summary>")
        lines.append("")
        for finding in info:
            lines.append(f"- {_escape(finding.title)} (`{finding.id}`)")
        lines.append("")
        lines.append("</details>")

    skipped = [c for c in result.checks if c.status != "ok"]
    if skipped:
        lines.append("")
        lines.append("<details><summary>Checks not run</summary>")
        lines.append("")
        for check in skipped:
            lines.append(f"- {_escape(check.name)}: {_escape(check.skipped or check.error)}")
        lines.append("")
        lines.append("</details>")
    lines.append("")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    lines = [
        "# SecureScope report",
        "",
        f"_{report.tool} {report.version} · generated {report.generated}_",
        "",
    ]
    if len(report.targets) > 1:
        lines.append("| Target | Grade | Critical | High | Medium | Low |")
        lines.append("|---|---|---|---|---|---|")
        for result in report.targets:
            s = result.summary
            c = s["counts"]
            lines.append(
                f"| {_escape(result.target)} | {s['grade']} | {c['critical']} | {c['high']} | "
                f"{c['medium']} | {c['low']} |"
            )
        lines.append("")
    if report.diff is not None:
        counts = report.diff["counts"]
        lines.append(
            f"**Compared with baseline:** {counts['new']} new, {counts['fixed']} fixed, "
            f"{counts['unchanged']} unchanged."
        )
        if report.diff["new"]:
            lines.append("")
            lines.append("New findings:")
            for raw in report.diff["new"]:
                lines.append(
                    f"- {BADGE[Severity(raw['severity'])]} {_escape(raw['title'])} (`{raw['id']}`) — "
                    f"{_escape(raw['target'])}"
                )
        if report.diff["fixed"]:
            lines.append("")
            lines.append("Fixed since baseline:")
            for raw in report.diff["fixed"]:
                lines.append(f"- ✅ {_escape(raw['title'])} (`{raw['id']}`) — {_escape(raw['target'])}")
        lines.append("")
    for result in report.targets:
        lines.append(render_target(result))
    lines.append("---")
    lines.append(
        "Scan only systems you own or are authorised to test. Findings are configuration observations; "
        "verify impact before reporting."
    )
    lines.append("")
    return "\n".join(lines)
