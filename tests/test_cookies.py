from securescope.checks.cookies import evaluate_cookies, parse_set_cookie
from securescope.findings import Severity
from securescope.http import split_folded_set_cookie


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, id):
    return next(f for f in findings if f.id == id)


def test_parse_set_cookie_attributes():
    cookie = parse_set_cookie(
        "sid=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Domain=.example.test; "
        "Secure; HttpOnly; SameSite=Lax"
    )
    assert cookie.name == "sid" and cookie.value == "abc123"
    assert cookie.secure and cookie.httponly
    assert cookie.samesite == "Lax"
    assert cookie.domain == ".example.test"
    assert cookie.path == "/"
    assert cookie.expires == "Wed, 21 Oct 2026 07:28:00 GMT"
    assert cookie.session_like


def test_parse_rejects_garbage():
    assert parse_set_cookie("") is None
    assert parse_set_cookie("no-equals-sign") is None


def test_split_folded_set_cookie_keeps_expires_commas():
    folded = "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, b=2; Path=/; Secure"
    assert split_folded_set_cookie(folded) == [
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/",
        "b=2; Path=/; Secure",
    ]


def test_hardened_session_cookie_is_clean():
    assert evaluate_cookies(["__Host-session=x; Secure; HttpOnly; Path=/; SameSite=Lax"], is_https=True) == []


def test_session_cookie_missing_everything():
    findings = evaluate_cookies(["sessionid=abc; Path=/"], is_https=True)
    assert ids(findings) == {"COOKIE-NO-SECURE", "COOKIE-NO-HTTPONLY", "COOKIE-NO-SAMESITE"}
    assert by_id(findings, "COOKIE-NO-SECURE").severity is Severity.HIGH  # session-like name bumps it
    assert by_id(findings, "COOKIE-NO-HTTPONLY").severity is Severity.MEDIUM


def test_non_session_cookie_is_rated_lower():
    findings = evaluate_cookies(["theme=dark; Path=/"], is_https=True)
    assert by_id(findings, "COOKIE-NO-SECURE").severity is Severity.MEDIUM
    assert by_id(findings, "COOKIE-NO-HTTPONLY").severity is Severity.LOW


def test_secure_flag_not_required_over_plain_http():
    findings = evaluate_cookies(["sessionid=abc; HttpOnly; SameSite=Lax"], is_https=False)
    assert "COOKIE-NO-SECURE" not in ids(findings)


def test_samesite_none_requires_secure():
    findings = evaluate_cookies(["x=1; SameSite=None; HttpOnly"], is_https=True)
    assert "COOKIE-SAMESITE-NONE-INSECURE" in ids(findings)
    assert "COOKIE-NO-SAMESITE" not in ids(findings)


def test_prefix_rules():
    findings = evaluate_cookies(
        ["__Host-a=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.test"], True
    )
    assert "COOKIE-HOST-PREFIX-INVALID" in ids(findings)
    findings = evaluate_cookies(["__Secure-a=1; HttpOnly; SameSite=Lax; Path=/"], True)
    assert "COOKIE-SECURE-PREFIX-INVALID" in ids(findings)


def test_broad_domain_on_session_cookie():
    findings = evaluate_cookies(["auth=1; Secure; HttpOnly; SameSite=Lax; Domain=.example.test"], True)
    assert ids(findings) == {"COOKIE-BROAD-DOMAIN"}


def test_cookie_values_are_redacted_in_evidence():
    findings = evaluate_cookies(["token=supersecretvalue123; Path=/"], True)
    for finding in findings:
        assert "supersecretvalue123" not in finding.evidence["header"]
        assert finding.evidence["header"].startswith("token=sup…")
