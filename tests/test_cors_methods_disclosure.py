from securescope.checks.cors import PROBE_ORIGIN, analyze_cors, evaluate_cors
from securescope.checks.disclosure import evaluate_disclosure
from securescope.checks.methods import evaluate_methods, parse_allow_header
from securescope.findings import Severity


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, id):
    return next(f for f in findings if f.id == id)


# --- CORS -----------------------------------------------------------------


def test_no_cors_headers_means_no_findings():
    probe = analyze_cors({"Content-Type": "text/html"})
    assert probe["origin"] is None and not probe["reflected"]
    assert evaluate_cors(probe) == []


def test_reflected_with_credentials_is_high():
    probe = analyze_cors(
        {
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        }
    )
    findings = evaluate_cors(probe)
    assert by_id(findings, "CORS-REFLECTED-CREDENTIALS").severity is Severity.HIGH
    assert "CORS-NO-VARY-ORIGIN" not in ids(findings)


def test_reflected_without_credentials_is_low():
    probe = analyze_cors({"access-control-allow-origin": PROBE_ORIGIN})
    findings = evaluate_cors(probe)
    assert by_id(findings, "CORS-REFLECTED").severity is Severity.LOW
    assert "CORS-NO-VARY-ORIGIN" in ids(findings)


def test_null_origin_with_credentials():
    probe = analyze_cors({"Access-Control-Allow-Origin": "https://app.test"})
    null_probe = analyze_cors(
        {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"}, "null"
    )
    findings = evaluate_cors(probe, null_probe)
    assert by_id(findings, "CORS-NULL-CREDENTIALS").severity is Severity.MEDIUM


def test_wildcard_with_credentials_is_low_and_without_is_fine():
    probe = analyze_cors({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert ids(evaluate_cors(probe)) == {"CORS-WILDCARD-CREDENTIALS"}
    probe = analyze_cors({"Access-Control-Allow-Origin": "*"})
    assert evaluate_cors(probe) == []


def test_fixed_allowlisted_origin_is_fine():
    probe = analyze_cors({"Access-Control-Allow-Origin": "https://app.test", "Vary": "Origin"})
    assert evaluate_cors(probe) == []


# --- methods --------------------------------------------------------------


def test_parse_allow_header():
    assert parse_allow_header("GET, POST,  get , OPTIONS") == ["GET", "POST", "OPTIONS"]
    assert parse_allow_header(None) == []


def test_trace_requires_an_echo_to_count():
    assert ids(evaluate_methods([], 200, trace_echoed=True)) == {"TRACE-ENABLED"}
    assert evaluate_methods([], 200, trace_echoed=False) == []
    assert evaluate_methods([], 405, trace_echoed=False) == []


def test_risky_methods_are_informational():
    findings = evaluate_methods(["GET", "PUT", "DELETE"], 405, False)
    finding = by_id(findings, "METHODS-RISKY-ADVERTISED")
    assert finding.severity is Severity.INFO
    assert finding.evidence["risky"] == ["PUT", "DELETE"]


# --- disclosure -----------------------------------------------------------


def test_server_version_disclosure():
    findings = evaluate_disclosure({"server": "nginx/1.18.0"})
    assert ids(findings) == {"SERVER-VERSION-DISCLOSED"}
    assert evaluate_disclosure({"server": "nginx"}) == []
    assert evaluate_disclosure({"server": "cloudflare"}) == []


def test_tech_headers():
    findings = evaluate_disclosure(
        {"x-powered-by": "PHP/8.1.2", "x-aspnet-version": "4.0.30319", "x-generator": "WordPress"}
    )
    assert len(findings) == 3
    assert (
        by_id([f for f in findings if f.evidence["name"] == "x-powered-by"], "TECH-HEADER-DISCLOSED").severity
        is Severity.LOW
    )
    generator = next(f for f in findings if f.evidence["name"] == "x-generator")
    assert generator.severity is Severity.INFO
