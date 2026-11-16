"""Self-contained HTML report.

Every value that originates from the target (header values, cookie
names, certificate fields, error strings) is HTML-escaped before it is
written. A scanned host must not be able to inject into the report that
describes it; test_reports.py pins this down.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

from securescope.findings import Finding, Severity
from securescope.scanner import Report, ScanResult

SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

CSS = """
:root{--bg:#0b1220;--bg2:#111b30;--bg3:#0a101c;--line:rgba(255,255,255,.1);--fg:#f1f4f9;--muted:#aeb8ca;--faint:#7d889c;
--accent:#f2b544;--critical:#ff6b6b;--high:#ff8f5e;--medium:#f2b544;--low:#6cc3ff;--info:#9aa5b8;--ok:#34d399;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f6f7fa;--bg2:#fff;--bg3:#eef0f5;--line:rgba(15,23,42,.12);--fg:#121a2c;--muted:#4e5a6e;
--faint:#7a8597;--accent:#b4802a;--critical:#c0392b;--high:#d35400;--medium:#b4802a;--low:#1f6fb2;--info:#5b6678;--ok:#0f9d6a;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 60px}header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:28px}
h1{margin:0;font-size:1.6rem;letter-spacing:-.02em}h1 span{color:var(--accent)}.meta{color:var(--faint);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82rem}
.target{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin:0 0 24px}
.target-head{display:flex;flex-wrap:wrap;align-items:center;gap:18px;margin-bottom:14px}.target-head h2{margin:0;font-size:1.15rem;word-break:break-all}
.grade{display:inline-grid;place-items:center;width:64px;height:64px;border-radius:14px;font-weight:800;font-size:1.6rem;border:2px solid currentColor}
.grade.g-A,.grade.g-Ap{color:var(--ok)}.grade.g-B{color:var(--low)}.grade.g-C{color:var(--medium)}.grade.g-D{color:var(--high)}.grade.g-F{color:var(--critical)}
.counts{display:flex;flex-wrap:wrap;gap:8px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem}
.counts button{cursor:pointer;background:transparent;color:inherit;border:1px solid currentColor;border-radius:6px;padding:3px 9px;font:inherit;letter-spacing:.04em;text-transform:uppercase;opacity:.9}
.counts button[aria-pressed="false"]{opacity:.4}.s-critical{color:var(--critical)}.s-high{color:var(--high)}.s-medium{color:var(--medium)}.s-low{color:var(--low)}.s-info{color:var(--info)}
.note{color:var(--muted);font-size:.92rem;margin:0 0 12px}.finding{border:1px solid var(--line);border-left:4px solid currentColor;border-radius:10px;padding:14px 16px;margin:10px 0;background:var(--bg)}
.finding[hidden]{display:none}.finding h3{margin:0 0 4px;font-size:1.02rem;color:var(--fg)}.finding .tag{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.74rem;letter-spacing:.06em;text-transform:uppercase}
.finding p{margin:8px 0;color:var(--muted);font-size:.95rem}.finding .rem{color:var(--fg)}.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:8px 0 0;font-size:.86rem}
.finding dt{color:var(--faint);font-family:ui-monospace,Menlo,Consolas,monospace}.finding dd{margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;color:var(--fg)}
.finding .refs a{color:var(--accent);font-size:.84rem;margin-right:10px;word-break:break-all}details{margin:12px 0 0}summary{cursor:pointer;color:var(--muted);font-size:.9rem}
pre{background:var(--bg3);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:.8rem;line-height:1.5;color:var(--fg)}
table.summary{width:100%;border-collapse:collapse;margin:0 0 24px;font-size:.92rem}table.summary th,table.summary td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
footer{color:var(--faint);font-size:.82rem;margin-top:30px}
"""

JS = """
document.querySelectorAll('.counts').forEach(function(bar){
  bar.querySelectorAll('button').forEach(function(btn){
    btn.addEventListener('click',function(){
      var on = btn.getAttribute('aria-pressed') !== 'true';
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      var sev = btn.dataset.sev, card = btn.closest('.target');
      card.querySelectorAll('.finding[data-sev="'+sev+'"]').forEach(function(f){ f.hidden = !on; });
    });
  });
});
"""


def _dl(evidence: dict[str, Any]) -> str:
    rows = []
    for key, value in evidence.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        rows.append(f"<dt>{escape(str(key))}</dt><dd>{escape(str(value))}</dd>")
    return f"<dl>{''.join(rows)}</dl>" if rows else ""


def _finding(finding: Finding) -> str:
    sev = finding.severity.value
    refs = "".join(
        f'<a href="{escape(ref, quote=True)}" rel="noopener noreferrer" target="_blank">{escape(ref)}</a>'
        for ref in finding.references
        if ref.startswith("https://")
    )
    cwe = f" · CWE-{int(finding.cwe)}" if finding.cwe else ""
    return (
        f'<article class="finding s-{sev}" data-sev="{sev}">'
        f'<div class="tag">{escape(SEVERITY_LABEL[finding.severity])} · {escape(finding.check)} · '
        f"{escape(finding.confidence.value)}{cwe}</div>"
        f"<h3>{escape(finding.title)} <span class=\"meta\">{escape(finding.id)}</span></h3>"
        f"<p>{escape(finding.description)}</p>"
        f'<p class="rem"><strong>Fix:</strong> {escape(finding.remediation)}</p>'
        f"{_dl(finding.evidence)}"
        f'<div class="refs">{refs}</div>'
        "</article>"
    )


def _target(result: ScanResult) -> str:
    summary = result.summary
    counts = summary["counts"]
    grade = summary["grade"]
    grade_class = "g-Ap" if grade == "A+" else f"g-{grade}"
    buttons = "".join(
        f'<button type="button" class="s-{sev.value}" data-sev="{sev.value}" aria-pressed="true">'
        f"{SEVERITY_LABEL[sev]} {counts[sev.value]}</button>"
        for sev in Severity
    )
    unreachable = (
        f'<p class="note">Target could not be fetched: {escape(str(result.error))}</p>' if not result.reachable else ""
    )
    findings = "".join(_finding(f) for f in result.findings) or '<p class="note">No findings.</p>'

    facts_rows = []
    for check in result.checks:
        status = check.status
        detail = check.skipped or check.error or ""
        facts_json = escape(json.dumps(check.facts, indent=2, ensure_ascii=False, default=str)) if check.facts else ""
        body = f"<pre>{facts_json}</pre>" if facts_json else ""
        facts_rows.append(
            f"<details><summary>{escape(check.name)} — {escape(status)}"
            f"{(' (' + escape(detail) + ')') if detail else ''}</summary>{body}</details>"
        )

    return (
        '<section class="target">'
        '<div class="target-head">'
        f'<div class="grade {grade_class}">{escape(grade)}</div>'
        f"<div><h2>{escape(result.target)}</h2>"
        f'<div class="meta">score {summary["score"]}/100 · {len(result.findings)} findings · '
        f"{result.duration:.1f}s · {escape(result.started)}</div></div>"
        "</div>"
        f'<div class="counts">{buttons}</div>'
        f"{unreachable}"
        f"{findings}"
        f'<details><summary>Raw check data ({len(result.checks)} checks)</summary>{"".join(facts_rows)}</details>'
        "</section>"
    )


def render_html(report: Report) -> str:
    rows = ""
    if len(report.targets) > 1:
        body_rows = "".join(
            f"<tr><td>{escape(t.target)}</td><td>{escape(t.summary['grade'])}</td>"
            f"<td>{t.summary['counts']['critical']}</td><td>{t.summary['counts']['high']}</td>"
            f"<td>{t.summary['counts']['medium']}</td><td>{t.summary['counts']['low']}</td></tr>"
            for t in report.targets
        )
        rows = (
            '<table class="summary"><thead><tr><th>Target</th><th>Grade</th><th>Critical</th><th>High</th>'
            f"<th>Medium</th><th>Low</th></tr></thead><tbody>{body_rows}</tbody></table>"
        )
    diff_html = ""
    if report.diff is not None:
        c = report.diff["counts"]
        diff_html = (
            f'<p class="note">Compared with baseline: <strong>{c["new"]} new</strong>, '
            f'{c["fixed"]} fixed, {c["unchanged"]} unchanged.</p>'
        )
    targets = "".join(_target(t) for t in report.targets)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>SecureScope report</title><style>{CSS}</style></head><body><div class=\"wrap\">"
        f"<header><h1><span>SecureScope</span> report</h1>"
        f'<div class="meta">v{escape(report.version)} · generated {escape(report.generated)}</div></header>'
        f"{rows}{diff_html}{targets}"
        "<footer>Scan only systems you own or are authorised to test. Findings are configuration "
        "observations backed by the evidence shown; verify impact before reporting them to anyone.</footer>"
        f"</div><script>{JS}</script></body></html>\n"
    )
