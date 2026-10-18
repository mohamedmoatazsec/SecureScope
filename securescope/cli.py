"""Command-line interface.

Exit codes:
  0  scan completed, no finding at or above --fail-on (or no threshold set)
  1  usage error, or no target could be scanned
  2  at least one finding at or above the --fail-on severity (new findings only when --baseline is given)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from securescope import __version__
from securescope.checks import ALL_CHECKS, CHECK_IDS
from securescope.config import ScanConfig, normalize_url, parse_header_option
from securescope.diff import diff_findings, load_baseline, new_findings
from securescope.findings import CheckResult, Finding, Severity, meets_threshold
from securescope.reports import FORMATS, render, write
from securescope.scanner import Report, ScanResult, scan_targets

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

GRADE_STYLE = {
    "A+": "bold green",
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securescope",
        description=(
            "Web security posture scanner: headers, CSP, cookies, TLS, CORS, HTTP methods and recon, "
            "with evidence-backed findings, a grade, and reports for humans and CI."
        ),
        epilog=(
            "examples:\n"
            "  securescope example.com\n"
            "  securescope https://app.example.com -f html -f json -o reports/\n"
            "  securescope -t targets.txt --fail-on high -f sarif\n"
            "  securescope https://app.example.com --proxy http://127.0.0.1:8080 \\\n"
            "      -H 'Authorization: Bearer …'\n"
            "  securescope https://app.example.com --baseline reports/last-good.json --fail-on medium\n\n"
            "Only scan systems you own or are explicitly authorised to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="URL or hostname (https:// assumed)")
    parser.add_argument(
        "-t", "--targets-file", metavar="FILE", help="file with one target per line (# comments allowed)"
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "-f",
        "--format",
        action="append",
        choices=FORMATS,
        metavar="FMT",
        help=f"write a report file; repeatable. One of: {', '.join(FORMATS)}",
    )
    out.add_argument(
        "-o", "--output", default=".", metavar="DIR", help="directory for report files (default: .)"
    )
    out.add_argument(
        "-n",
        "--name",
        default="securescope-report",
        metavar="NAME",
        help="report file name without extension",
    )
    out.add_argument(
        "--stdout",
        choices=FORMATS,
        metavar="FMT",
        help="print one report format to stdout (console output goes to stderr)",
    )
    out.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="one summary line per target instead of the full console report",
    )
    out.add_argument("--no-color", action="store_true", help="plain console output")
    out.add_argument(
        "--show-info", action="store_true", help="include informational findings in the console report"
    )

    gate = parser.add_argument_group("CI gate")
    gate.add_argument(
        "--fail-on",
        metavar="SEV",
        help="exit 2 if any finding is at least this severity (critical, high, medium, low)",
    )
    gate.add_argument(
        "--baseline",
        metavar="JSON",
        help="previous JSON report; --fail-on then only counts findings that are new",
    )

    checks = parser.add_argument_group("checks")
    checks.add_argument("--checks", metavar="LIST", help="comma-separated check ids to run (default: all)")
    checks.add_argument("--skip-checks", metavar="LIST", help="comma-separated check ids to skip")
    checks.add_argument("--list-checks", action="store_true", help="list check ids and exit")
    checks.add_argument("--ports", action="store_true", help="probe common TCP ports (opt-in)")
    checks.add_argument("--subdomains", action="store_true", help="resolve common subdomains (opt-in)")
    checks.add_argument("--whois", action="store_true", help="WHOIS lookup (opt-in)")

    net = parser.add_argument_group("connection")
    net.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP(S) proxy for all HTTP requests, e.g. http://127.0.0.1:8080 (Burp)",
    )
    net.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header; repeatable",
    )
    net.add_argument(
        "--cookie", action="append", default=[], metavar="name=value", help="cookie to send; repeatable"
    )
    net.add_argument("--user-agent", metavar="UA", help="override the User-Agent")
    net.add_argument(
        "--insecure", action="store_true", help="do not verify TLS certificates for HTTP requests"
    )
    net.add_argument(
        "--timeout", type=float, default=10.0, metavar="SEC", help="per-request timeout (default: 10)"
    )
    net.add_argument(
        "--retries", type=int, default=1, metavar="N", help="retries on 502/503/504 (default: 1)"
    )
    net.add_argument(
        "--concurrency", type=int, default=4, metavar="N", help="targets scanned in parallel (default: 4)"
    )

    parser.add_argument("--version", action="version", version=f"SecureScope {__version__}")
    return parser


def read_targets_file(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def config_from_args(args: argparse.Namespace) -> ScanConfig:
    headers = dict(parse_header_option(h) for h in args.header)
    cookies = {}
    for raw in args.cookie:
        if "=" not in raw:
            raise ValueError(f"cookie {raw!r} must look like name=value")
        name, _, value = raw.partition("=")
        cookies[name.strip()] = value.strip()

    def split(value: str | None) -> list[str] | None:
        if value is None:
            return None
        ids = [v.strip() for v in value.split(",") if v.strip()]
        unknown = [i for i in ids if i not in CHECK_IDS]
        if unknown:
            raise ValueError(f"unknown check id(s): {', '.join(unknown)} (see --list-checks)")
        return ids

    return ScanConfig(
        timeout=args.timeout,
        retries=args.retries,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        user_agent=args.user_agent,
        verify_tls=not args.insecure,
        checks=split(args.checks),
        skip_checks=split(args.skip_checks) or [],
        ports=args.ports,
        subdomains=args.subdomains,
        whois=args.whois,
    )


# ----------------------------------------------------------------- console output


def banner(console: Console) -> None:
    console.print(
        Panel.fit(
            f"[bold]SecureScope[/bold] [dim]v{__version__}[/dim]\n[dim]web security posture scanner[/dim]",
            border_style="yellow",
        )
    )


def _evidence_summary(finding: Finding) -> str:
    bits = []
    keys = (
        "name",
        "directive",
        "value",
        "header",
        "allow_origin",
        "status",
        "not_after",
        "accepted",
        "error",
    )
    for key in keys:
        value = finding.evidence.get(key)
        if value in (None, "", [], {}):
            continue
        if key == "value" and finding.evidence.get("directive"):
            continue  # the directive names the problem; the whole policy is in the reports
        text = str(value)
        if len(text) > 60:
            text = text[:59] + "…"
        bits.append(f"{key}={text}")
        if len(bits) == 2:
            break
    return "  ".join(bits)


def print_target(console: Console, result: ScanResult, show_info: bool) -> None:
    summary = result.summary
    grade = summary["grade"]
    counts = summary["counts"]
    title = Text.assemble(
        (f" {grade} ", GRADE_STYLE.get(grade, "bold")),
        ("  ", ""),
        (result.target, "bold"),
        (f"   score {summary['score']}/100", "dim"),
    )
    console.print()
    console.rule(title, align="left")
    if not result.reachable:
        console.print(f"[red]Could not fetch the target:[/red] {result.error}")

    console.print(
        "  ".join(
            f"[{SEVERITY_STYLE[sev]}]{counts[sev.value]} {sev.value}[/]"
            for sev in Severity
            if counts[sev.value] or sev != Severity.INFO
        )
    )

    findings = [f for f in result.findings if show_info or f.severity != Severity.INFO]
    if findings:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, expand=True)
        table.add_column("Severity", width=9, no_wrap=True)
        table.add_column("Finding", ratio=3)
        table.add_column("Evidence", ratio=2, style="dim")
        for finding in findings:
            table.add_row(
                f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity.value.upper()}[/]",
                f"{finding.title}\n[dim]{finding.id} · {finding.check}[/dim]",
                _evidence_summary(finding),
            )
        console.print(table)
    hidden = len(result.findings) - len(findings)
    if hidden:
        console.print(f"[dim]{hidden} informational finding(s) hidden; pass --show-info to list them.[/dim]")

    not_run = [c for c in result.checks if c.status != "ok"]
    if not_run:
        console.print(
            "[dim]Not run: " + "; ".join(f"{c.name} ({c.skipped or c.error})" for c in not_run) + "[/dim]"
        )


def print_summary_line(console: Console, result: ScanResult) -> None:
    s = result.summary
    c = s["counts"]
    console.print(
        f"[{GRADE_STYLE.get(s['grade'], 'bold')}]{s['grade']:>2}[/] {result.target}  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} low={c['low']} info={c['info']}"
        + ("" if result.reachable else f"  [red]unreachable: {result.error}[/red]")
    )


def print_diff(console: Console, diff: dict) -> None:
    c = diff["counts"]
    console.print()
    console.print(
        f"[bold]Baseline comparison:[/bold] {c['new']} new, {c['fixed']} fixed, {c['unchanged']} unchanged"
    )
    for raw in diff["new"]:
        sev = Severity(raw["severity"])
        console.print(
            f"  [{SEVERITY_STYLE[sev]}]NEW[/]   {raw['title']}  [dim]{raw['id']} · {raw['target']}[/dim]"
        )
    for raw in diff["fixed"]:
        console.print(f"  [green]FIXED[/] {raw['title']}  [dim]{raw['id']} · {raw['target']}[/dim]")


# ----------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        for check in ALL_CHECKS:
            print(f"{check.id:<12} {check.name}")
        return 0

    console = Console(stderr=bool(args.stdout), no_color=args.no_color, highlight=False)

    targets = list(args.targets)
    if args.targets_file:
        try:
            targets.extend(read_targets_file(args.targets_file))
        except OSError as exc:
            parser.error(f"cannot read targets file: {exc}")
    if not targets:
        parser.error("no target given (pass a URL, or -t FILE)")

    try:
        targets = [normalize_url(t) for t in targets]
        config = config_from_args(args)
        threshold = Severity.parse(args.fail_on) if args.fail_on else None
        baseline = load_baseline(args.baseline) if args.baseline else None
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    if not args.quiet and not args.stdout:
        banner(console)
        console.print(f"[dim]Scanning {len(targets)} target(s)…[/dim]")

    def progress(target: str, check: CheckResult) -> None:
        if args.quiet or args.stdout:
            return
        mark = "[green]✓[/green]" if check.status == "ok" else "[dim]–[/dim]"
        count = len(check.findings)
        console.print(
            f"  {mark} {check.name:<24} [dim]{target}[/dim]  {count} finding(s)"
            + (f"  [dim]{check.skipped or check.error}[/dim]" if check.status != "ok" else "")
        )

    report: Report = scan_targets(targets, config, concurrency=args.concurrency, progress=progress)

    if baseline is not None:
        report.diff = diff_findings(report.findings, baseline)

    for result in report.targets:
        if args.quiet:
            print_summary_line(console, result)
        else:
            print_target(console, result, show_info=args.show_info)
    if report.diff is not None:
        print_diff(console, report.diff)

    written = []
    for fmt in args.format or []:
        written.append(write(report, fmt, args.output, args.name))
    if written:
        console.print()
        for path in written:
            console.print(f"[green]Report written:[/green] {path}")
    if args.stdout:
        sys.stdout.write(render(report, args.stdout))
        sys.stdout.flush()

    if all(not t.reachable for t in report.targets):
        console.print("[red]No target could be scanned.[/red]")
        return 1

    if threshold is not None:
        considered = new_findings(report.findings, baseline) if baseline is not None else report.findings
        failing = [f for f in considered if meets_threshold(f, threshold)]
        if failing:
            console.print(
                f"\n[bold red]FAIL[/bold red] {len(failing)} finding(s) at or above {threshold.value}"
                + (" (new since baseline)" if baseline is not None else "")
            )
            return 2
        console.print(f"\n[bold green]PASS[/bold green] no findings at or above {threshold.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
