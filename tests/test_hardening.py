"""The scanner's own attack surface: a hostile target must not break or hijack the reports."""

from io import StringIO

import pytest
from rich.console import Console
from webserver import Profile

from securescope import http as http_module
from securescope.cli import print_diff, print_target
from securescope.config import ScanConfig
from securescope.diff import load_baseline
from securescope.findings import EVIDENCE_LIMIT, CheckResult, Finding, Severity
from securescope.http import BODY_LIMIT, MAX_REDIRECTS, RedirectBlocked, ScanSession, is_internal_host
from securescope.reports import render
from securescope.reports.csv_report import neutralize
from securescope.scanner import Report, ScanResult, scan_target

HOSTILE = (
    "[/] [bold red]x[/bold red] [link=https://evil.test]click[/link] "
    "<img src=x onerror=alert(1)> `tick` | pipe"
)


def hostile_result():
    finding = Finding(
        id="SERVER-VERSION-DISCLOSED",
        title=f"Server header reveals the software version ({HOSTILE})",
        severity=Severity.LOW,
        description="d",
        remediation="r",
        check="disclosure",
        evidence={"name": "Server", "value": HOSTILE},
        target="https://t.test/",
    )
    checks = [
        CheckResult(id="disclosure", name="Information disclosure", findings=[finding]),
        CheckResult(id="tls", name="TLS and transport", error=f"boom {HOSTILE}"),
    ]
    return ScanResult(
        target="https://t.test/", started="x", duration=0.1, reachable=False, error=HOSTILE, checks=checks
    )


def test_console_output_survives_rich_markup_in_target_data():
    console = Console(file=StringIO(), no_color=True, highlight=False, width=120)
    result = hostile_result()
    print_target(console, result, show_info=True)
    print_diff(
        console,
        {
            "counts": {"new": 1, "fixed": 1, "unchanged": 0},
            "new": [result.findings[0].to_dict()],
            "fixed": [result.findings[0].to_dict()],
        },
    )
    out = console.file.getvalue()
    assert "[/]" in out  # printed literally, not interpreted (and no MarkupError)
    assert "evil.test" in out


def test_csv_formula_injection_is_neutralised():
    assert neutralize("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert neutralize("+1") == "'+1" and neutralize("-1") == "'-1" and neutralize("@x") == "'@x"
    assert neutralize("nginx") == "nginx" and neutralize("") == ""
    result = hostile_result()
    result.checks[0].findings[0].title = "=cmd|' /C calc'!A0"
    csv_text = render(Report(targets=[result]), "csv")
    assert "\n" in csv_text and "'=cmd" in csv_text
    assert ",=cmd" not in csv_text


def test_markdown_neutralises_html_and_code_span_breakouts():
    md = render(Report(targets=[hostile_result()]), "md")
    assert "&lt;img src=x onerror=alert(1)&gt;" in md  # the title is HTML-escaped
    # raw HTML may only ever appear inside a code span, where Markdown renders it literally
    for line in md.splitlines():
        if "<img" in line:
            segments = line.split("`")
            assert all("<img" not in seg for seg in segments[0::2]), line
    # evidence stays inside its code span: backticks from the target are replaced
    assert "`tick`" not in md
    assert "[link=https://evil.test]" in md  # harmless in Markdown, must survive as text


def test_evidence_and_title_are_capped():
    finding = Finding(
        id="X",
        title="t" * 5000,
        severity=Severity.LOW,
        description="d",
        remediation="r",
        check="c",
        evidence={"value": "v" * 5000, "list": ["x" * 5000] * 100, "nested": {"k": "y" * 5000}},
    )
    assert len(finding.evidence["value"]) == EVIDENCE_LIMIT
    assert len(finding.evidence["list"]) == 50 and len(finding.evidence["list"][0]) == EVIDENCE_LIMIT
    assert len(finding.evidence["nested"]["k"]) == EVIDENCE_LIMIT
    assert len(finding.title) == 300


@pytest.mark.parametrize(
    "host, internal",
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("app.localhost", True),
        ("10.1.2.3", True),
        ("172.16.0.9", True),
        ("192.168.1.1", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),
        ("fd00::1", True),
        ("8.8.8.8", False),
        ("example.test", False),
        ("", False),
    ],
)
def test_is_internal_host(host, internal):
    assert is_internal_host(host) is internal


def test_response_bodies_are_capped(http_server):
    with http_server(Profile(body="A" * (BODY_LIMIT + 500_000), content_type="text/html")) as server:
        with ScanSession(ScanConfig(timeout=10, retries=0)) as session:
            response = session.get(server.url)
        assert len(response.content) == BODY_LIMIT
        assert response.securescope_truncated is True

        result = scan_target(server.url, ScanConfig(timeout=10, retries=0, checks=["target", "headers"]))
    assert "RESPONSE-BODY-TRUNCATED" in {f.id for f in result.findings}
    assert result.check("target").facts["body_truncated"] is True


def test_redirect_loops_are_cut_off(http_server):
    with http_server(Profile(redirect_to="/")) as server:
        with ScanSession(ScanConfig(timeout=5, retries=0)) as session:
            with pytest.raises(RedirectBlocked) as exc:
                session.get(server.url)
        assert f"more than {MAX_REDIRECTS} redirects" in str(exc.value)

        result = scan_target(server.url, ScanConfig(timeout=5, retries=0, checks=["target"]))
    assert result.reachable  # the last redirect response is still analysed
    assert "REDIRECT-NOT-FOLLOWED" in {f.id for f in result.findings}


def test_redirect_into_internal_space_is_refused(http_server, monkeypatch):
    # The test server lives on 127.0.0.1, so pretend that is public and only "localhost" is internal.
    monkeypatch.setattr(http_module, "is_internal_host", lambda host: host == "localhost")
    with http_server(Profile()) as server:
        profile = server.httpd.RequestHandlerClass.profile
        profile.redirect_to = f"http://localhost:{server.port}/landing"
        with ScanSession(ScanConfig(timeout=5, retries=0)) as session:
            with pytest.raises(RedirectBlocked) as exc:
                session.get(server.url)
        assert "internal address" in str(exc.value)
        assert exc.value.location.startswith("http://localhost:")

        result = scan_target(server.url, ScanConfig(timeout=5, retries=0, checks=["target"]))
        profile.redirect_to = None
    ids = {f.id for f in result.findings}
    assert "REDIRECT-TO-INTERNAL-ADDRESS" in ids


def test_cross_host_redirect_is_reported(http_server):
    with http_server(Profile()) as server:
        profile = server.httpd.RequestHandlerClass.profile
        profile.redirect_to = f"http://localhost:{server.port}/landing"
        result = scan_target(server.url, ScanConfig(timeout=5, retries=0, checks=["target", "headers"]))
        profile.redirect_to = None
    ids = {f.id for f in result.findings}
    assert "TARGET-REDIRECTED" in ids
    assert result.check("target").facts["final_url"].startswith("http://localhost:")
    assert len(result.check("target").facts["redirects"]) == 1


def test_https_to_http_downgrade_redirect_is_flagged(http_server):
    # Two servers share one profile: the TLS one redirects "/" to a plain-HTTP landing page.
    with http_server(Profile()) as plain, http_server(Profile(), tls=True) as secure:
        profile = secure.httpd.RequestHandlerClass.profile
        profile.redirect_to = f"http://127.0.0.1:{plain.port}/landing"
        result = scan_target(
            secure.url, ScanConfig(timeout=5, retries=0, verify_tls=False, checks=["target"])
        )
        profile.redirect_to = None
    assert result.reachable and result.error is None
    finding = next(f for f in result.findings if f.id == "REDIRECT-HTTPS-TO-HTTP")
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["location"].startswith("http://127.0.0.1:")


def test_malformed_baseline_is_a_clear_error(tmp_path):
    bad = tmp_path / "b.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline(str(bad))
    bad.write_text('{"tool": "other"}')
    with pytest.raises(ValueError, match="not a SecureScope"):
        load_baseline(str(bad))
    bad.write_text('{"tool": "SecureScope", "targets": [{"findings": [{"severity": "high"}]}]}')
    with pytest.raises(ValueError, match="malformed finding"):
        load_baseline(str(bad))
