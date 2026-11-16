from securescope.checks.headers import evaluate_headers, evaluate_hsts, parse_hsts
from securescope.findings import Severity

GOOD = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
}


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, id):
    return next(f for f in findings if f.id == id)


def test_hardened_response_has_no_findings():
    assert evaluate_headers(GOOD, is_https=True, is_html=True) == []


def test_parse_hsts():
    assert parse_hsts("max-age=31536000; includeSubDomains; preload") == {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True,
    }
    assert parse_hsts('max-age="600"')["max_age"] == 600
    assert parse_hsts("includeSubDomains")["max_age"] is None


def test_hsts_variants():
    assert by_id(evaluate_hsts(None, True), "HSTS-MISSING").severity is Severity.HIGH
    assert evaluate_hsts(None, False) == []  # not applicable over http
    assert ids(evaluate_hsts("includeSubDomains", True)) == {"HSTS-INVALID"}
    assert ids(evaluate_hsts("max-age=0", True)) == {"HSTS-DISABLED"}
    short = evaluate_hsts("max-age=600", True)
    assert ids(short) == {"HSTS-SHORT-MAX-AGE", "HSTS-NO-SUBDOMAINS"}
    assert by_id(short, "HSTS-SHORT-MAX-AGE").evidence["max_age"] == 600
    assert ids(evaluate_hsts("max-age=31536000", True)) == {"HSTS-NO-SUBDOMAINS"}
    assert evaluate_hsts("max-age=31536000; includeSubDomains", True) == []


def test_missing_everything_on_html_page():
    findings = evaluate_headers({"content-type": "text/html"}, is_https=True, is_html=True)
    assert {
        "HSTS-MISSING",
        "XCTO-MISSING",
        "CLICKJACKING-UNPROTECTED",
        "REFERRER-POLICY-MISSING",
        "PERMISSIONS-POLICY-MISSING",
        "COOP-MISSING",
    } <= ids(findings)
    assert by_id(findings, "CLICKJACKING-UNPROTECTED").severity is Severity.MEDIUM


def test_json_api_response_skips_html_only_checks():
    findings = evaluate_headers({"content-type": "application/json"}, is_https=True, is_html=False)
    assert "CLICKJACKING-UNPROTECTED" not in ids(findings)
    assert "PERMISSIONS-POLICY-MISSING" not in ids(findings)
    assert "COOP-MISSING" not in ids(findings)


def test_clickjacking_variants():
    headers = dict(GOOD)
    del headers["content-security-policy"]
    headers["x-frame-options"] = "DENY"
    findings = evaluate_headers(headers, True, True)
    assert ids(findings) == {"XFO-ONLY"}

    headers["x-frame-options"] = "ALLOW-FROM https://partner.test"
    assert ids(evaluate_headers(headers, True, True)) == {"XFO-INVALID"}

    headers["x-frame-options"] = "sameorigin"
    assert ids(evaluate_headers(headers, True, True)) == {"XFO-ONLY"}

    headers = dict(GOOD)
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors *"
    assert ids(evaluate_headers(headers, True, True)) == {"FRAME-ANCESTORS-WILDCARD"}


def test_xcto_wrong_value():
    headers = dict(GOOD, **{"x-content-type-options": "sniff"})
    assert ids(evaluate_headers(headers, True, True)) == {"XCTO-INVALID"}


def test_referrer_policy_values():
    headers = dict(GOOD, **{"referrer-policy": "unsafe-url"})
    assert ids(evaluate_headers(headers, True, True)) == {"REFERRER-POLICY-WEAK"}
    # last recognised token wins
    headers["referrer-policy"] = "unsafe-url, strict-origin-when-cross-origin"
    assert evaluate_headers(headers, True, True) == []
    headers["referrer-policy"] = "no-referrer"
    assert evaluate_headers(headers, True, True) == []


def test_legacy_xss_protection_and_public_cache():
    headers = dict(GOOD, **{"x-xss-protection": "1; mode=block", "cache-control": "public, max-age=60"})
    findings = evaluate_headers(headers, True, True)
    assert ids(findings) == {"XSS-PROTECTION-LEGACY", "CACHE-PUBLIC-HTML"}
    assert by_id(findings, "CACHE-PUBLIC-HTML").severity is Severity.INFO
    headers["x-xss-protection"] = "0"
    headers["cache-control"] = "no-store"
    assert evaluate_headers(headers, True, True) == []
