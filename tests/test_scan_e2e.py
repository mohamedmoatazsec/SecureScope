"""End-to-end scans against the local test server (no internet access needed)."""

import json

import pytest
from webserver import Profile

from securescope.cli import main
from securescope.config import ScanConfig
from securescope.scanner import scan_target, scan_targets

WEAK = Profile(
    headers={
        "Server": "nginx/1.18.0",
        "X-Powered-By": "PHP/8.1.2",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https:",
        "X-Frame-Options": "ALLOW-FROM https://example.test",
        "Referrer-Policy": "unsafe-url",
    },
    cookies=[
        "sessionid=abc123def456; Path=/",
        "__Host-csrf=zzz; Secure; Path=/; Domain=example.test; SameSite=None",
    ],
    reflect_origin=True,
    allow_credentials=True,
    trace=True,
    allow_header="GET, HEAD, OPTIONS, PUT, DELETE, TRACE",
    robots="User-agent: *\nDisallow: /admin\n",
)

STRONG = Profile(
    headers={
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; report-to csp"
        ),
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    },
    cookies=["__Host-session=abc123def456; Secure; HttpOnly; Path=/; SameSite=Lax"],
    security_txt="Contact: mailto:security@example.test\nExpires: 2030-01-01T00:00:00Z\n",
    robots="User-agent: *\nDisallow:\n",
)


def ids(result):
    return {f.id for f in result.findings}


def test_weak_server_over_http(http_server):
    with http_server(WEAK) as server:
        result = scan_target(server.url, ScanConfig(timeout=5))

    assert result.reachable
    found = ids(result)
    assert {
        "CORS-REFLECTED-CREDENTIALS",
        "CORS-NULL-CREDENTIALS",
        "CSP-UNSAFE-INLINE",
        "CSP-BROAD-SCRIPT-SOURCE",
        "XFO-INVALID",
        "REFERRER-POLICY-WEAK",
        "COOKIE-NO-HTTPONLY",
        "COOKIE-HOST-PREFIX-INVALID",
        "TRACE-ENABLED",
        "METHODS-RISKY-ADVERTISED",
        "SERVER-VERSION-DISCLOSED",
        "TECH-HEADER-DISCLOSED",
        "SECURITY-TXT-MISSING",
        "HTTP-ONLY-TARGET",
    } <= found
    # HTTPS-only checks must not fire over plain http
    assert "HSTS-MISSING" not in found
    assert "COOKIE-NO-SECURE" not in found
    assert result.summary["grade"] == "F"
    assert result.check("tls").status == "skipped"
    assert result.check("robots").facts["disallow"] == ["/admin"]
    assert result.check("ports").status == "skipped"


def test_strong_server_over_tls(http_server):
    with http_server(STRONG, tls=True) as server:
        result = scan_target(server.url, ScanConfig(timeout=5, verify_tls=False))

    found = ids(result)
    tls = result.check("tls")
    assert tls.status == "ok", tls.error
    assert tls.facts["protocols"]["TLSv1.2"] == "accepted"
    # self-signed test certificate: untrusted + about to expire are the only expected findings
    assert found <= {
        "TLS-CERT-UNTRUSTED",
        "TLS-CERT-EXPIRING",
        "TLS-CERT-EXPIRING-SOON",
        "CSP-UNSAFE-INLINE-FALLBACK",
    }
    assert "TLS-CERT-UNTRUSTED" in found
    assert result.check("securitytxt").facts["found"] is True
    assert result.check("cookies").facts["count"] == 1


def test_unreachable_target_does_not_raise():
    result = scan_target("http://127.0.0.1:9/", ScanConfig(timeout=2, retries=0))
    assert not result.reachable
    assert result.error
    assert all(c.status in ("skipped", "error") or c.id in ("dns", "tls") for c in result.checks)


def test_check_selection(http_server):
    with http_server(STRONG) as server:
        result = scan_target(server.url, ScanConfig(timeout=5, checks=["headers", "cookies"]))
    assert [c.id for c in result.checks] == ["headers", "cookies"]
    with http_server(STRONG) as server:
        result = scan_target(server.url, ScanConfig(timeout=5, skip_checks=["cors", "methods"]))
    assert "cors" not in [c.id for c in result.checks]


def test_scan_targets_dedupes_and_bundles(http_server):
    with http_server(STRONG) as server:
        report = scan_targets([server.url, server.url, server.url.rstrip("/")], ScanConfig(timeout=5))
    assert len(report.targets) == 1
    assert report.to_dict()["summary"]["total"] == len(report.findings)


def test_cli_exit_codes_and_reports(http_server, tmp_path, capsys):
    with http_server(WEAK) as server:
        code = main(
            [
                server.url,
                "-f",
                "json",
                "-f",
                "sarif",
                "-o",
                str(tmp_path),
                "-n",
                "scan",
                "--fail-on",
                "high",
                "-q",
            ]
        )
        assert code == 2
        assert (tmp_path / "scan.json").exists() and (tmp_path / "scan.sarif").exists()

        # a baseline containing every current finding → nothing new → passes
        code = main([server.url, "--baseline", str(tmp_path / "scan.json"), "--fail-on", "low", "-q"])
        assert code == 0
        out = capsys.readouterr().out
        assert "0 new" in out

        code = main([server.url, "--fail-on", "critical", "-q"])
        assert code == 0


def test_cli_stdout_json(http_server, capsys):
    with http_server(STRONG) as server:
        code = main([server.url, "--stdout", "json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["targets"][0]["target"] == server.url


def test_cli_unreachable_returns_one(capsys):
    assert main(["http://127.0.0.1:9/", "-q", "--timeout", "2", "--retries", "0"]) == 1


def test_cli_rejects_bad_input():
    with pytest.raises(SystemExit):
        main([])
    with pytest.raises(SystemExit):
        main(["example.test", "--checks", "nope"])
    with pytest.raises(SystemExit):
        main(["example.test", "-H", "no-colon"])
    with pytest.raises(SystemExit):
        main(["ftp://example.test"])


def test_cli_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "csp" in out and "tls" in out
