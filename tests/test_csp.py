from securescope.checks.csp import evaluate_csp, parse_csp
from securescope.findings import Severity

STRICT = (
    "default-src 'none'; script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'; report-to csp-endpoint"
)


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, id):
    return next(f for f in findings if f.id == id)


def test_parse_handles_duplicates_and_unknown_directives():
    policy = parse_csp("default-src 'self'; script-src 'self'; script-src 'none'; scripts-src x; ")
    assert policy.directives["script-src"] == ["'self'"]
    assert policy.duplicates == ["script-src"]
    assert policy.unknown == ["scripts-src"]
    assert policy.effective("img-src") == ["'self'"]


def test_missing_policy_is_high_on_html_and_low_elsewhere():
    assert by_id(evaluate_csp(None, None, is_html=True), "CSP-MISSING").severity is Severity.HIGH
    assert by_id(evaluate_csp(None, None, is_html=False), "CSP-MISSING").severity is Severity.LOW


def test_report_only_is_flagged_not_treated_as_enforced():
    findings = evaluate_csp(None, "default-src 'self'")
    assert ids(findings) == {"CSP-REPORT-ONLY"}


def test_strict_policy_yields_nothing_above_info():
    findings = evaluate_csp(STRICT)
    assert all(f.severity is Severity.INFO for f in findings), ids(findings)


def test_no_script_restriction():
    findings = evaluate_csp("img-src 'self'; frame-ancestors 'none'")
    assert "CSP-NO-SCRIPT-RESTRICTION" in ids(findings)
    assert by_id(findings, "CSP-NO-SCRIPT-RESTRICTION").severity is Severity.HIGH


def test_unsafe_inline_without_nonce_is_high_with_nonce_is_info():
    findings = evaluate_csp("script-src 'self' 'unsafe-inline'; object-src 'none'")
    assert by_id(findings, "CSP-UNSAFE-INLINE").severity is Severity.HIGH
    findings = evaluate_csp("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'")
    assert "CSP-UNSAFE-INLINE" not in ids(findings)
    assert "CSP-UNSAFE-INLINE-FALLBACK" in ids(findings)


def test_unsafe_eval_and_broad_sources():
    findings = evaluate_csp("default-src 'self' 'unsafe-eval' https: data:")
    assert by_id(findings, "CSP-UNSAFE-EVAL").severity is Severity.MEDIUM
    broad = by_id(findings, "CSP-BROAD-SCRIPT-SOURCE")
    assert broad.severity is Severity.HIGH
    assert broad.evidence["sources"] == ["data:", "https:"]
    assert broad.evidence["directive"] == "default-src"


def test_strict_dynamic_makes_host_sources_irrelevant():
    findings = evaluate_csp("script-src 'nonce-x' 'strict-dynamic' https: *.cdn.test; object-src 'none'")
    assert "CSP-BROAD-SCRIPT-SOURCE" not in ids(findings)
    assert "CSP-WILDCARD-HOST" not in ids(findings)


def test_wildcard_host_is_low():
    findings = evaluate_csp("script-src 'self' *.example.test; object-src 'none'")
    assert by_id(findings, "CSP-WILDCARD-HOST").severity is Severity.LOW


def test_object_src_and_base_uri_defaults():
    findings = evaluate_csp("script-src 'self'")
    assert "CSP-OBJECT-SRC" in ids(findings)
    assert "CSP-BASE-URI" in ids(findings)
    # default-src 'none' covers object-src
    findings = evaluate_csp("default-src 'none'; script-src 'self'; base-uri 'self'")
    assert "CSP-OBJECT-SRC" not in ids(findings)
    assert "CSP-BASE-URI" not in ids(findings)


def test_duplicate_and_unknown_directives_are_reported():
    findings = evaluate_csp("script-src 'self'; script-src 'none'; object-src 'none'; scripts-src 'self'")
    assert "CSP-DUPLICATE-DIRECTIVE" in ids(findings)
    unknown = by_id(findings, "CSP-UNKNOWN-DIRECTIVE")
    assert unknown.evidence["directive"] == "scripts-src"


def test_evidence_never_includes_a_value_longer_than_the_excerpt_limit():
    huge = "script-src " + " ".join(f"https://h{i}.test" for i in range(200))
    findings = evaluate_csp(huge)
    assert all(len(f.evidence.get("value", "")) <= 400 for f in findings)
