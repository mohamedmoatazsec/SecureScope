from datetime import datetime, timezone

from securescope.checks.tls import evaluate_transport, summarize_certificate
from securescope.findings import Severity

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)

CERT = {
    "subject": ((("commonName", "www.example.test"),),),
    "issuer": ((("organizationName", "Example CA"),),),
    "subjectAltName": (("DNS", "www.example.test"), ("DNS", "example.test")),
    "notBefore": "Sep  1 00:00:00 2026 GMT",
    "notAfter": "Nov 30 23:59:59 2026 GMT",
    "serialNumber": "01",
}

GOOD_INFO = {
    "verified": True,
    "verify_error": None,
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "certificate": summarize_certificate(CERT, NOW),
}
GOOD_PROTOCOLS = {"TLSv1": "refused", "TLSv1.1": "refused", "TLSv1.2": "accepted", "TLSv1.3": "accepted"}
GOOD_REDIRECT = {
    "tested": True,
    "host": "www.example.test",
    "status": 301,
    "location": "https://www.example.test/",
    "to_https": True,
}


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, id):
    return next(f for f in findings if f.id == id)


def test_summarize_certificate():
    summary = summarize_certificate(CERT, NOW)
    assert summary["subject"] == "www.example.test"
    assert summary["issuer"] == "Example CA"
    assert summary["sans"] == ["www.example.test", "example.test"]
    assert summary["not_after"] == "2026-11-30"
    assert summary["days_remaining"] == 43


def test_good_transport_has_no_findings():
    assert evaluate_transport(GOOD_INFO, GOOD_PROTOCOLS, GOOD_REDIRECT) == []


def test_untrusted_certificate():
    info = dict(GOOD_INFO, verified=False, verify_error="self-signed certificate")
    findings = evaluate_transport(info, GOOD_PROTOCOLS, GOOD_REDIRECT)
    finding = by_id(findings, "TLS-CERT-UNTRUSTED")
    assert finding.severity is Severity.HIGH
    assert "self-signed" in finding.evidence["error"]


def test_expiry_windows():
    def with_days(days):
        return dict(GOOD_INFO, certificate=dict(GOOD_INFO["certificate"], days_remaining=days))

    assert ids(evaluate_transport(with_days(-3), GOOD_PROTOCOLS, GOOD_REDIRECT)) == {"TLS-CERT-EXPIRED"}
    assert ids(evaluate_transport(with_days(1), GOOD_PROTOCOLS, GOOD_REDIRECT)) == {"TLS-CERT-EXPIRING"}
    assert ids(evaluate_transport(with_days(25), GOOD_PROTOCOLS, GOOD_REDIRECT)) == {"TLS-CERT-EXPIRING-SOON"}
    assert by_id(
        evaluate_transport(with_days(1), GOOD_PROTOCOLS, GOOD_REDIRECT), "TLS-CERT-EXPIRING"
    ).title.endswith("in 1 day")
    assert evaluate_transport(with_days(60), GOOD_PROTOCOLS, GOOD_REDIRECT) == []


def test_legacy_protocols():
    protocols = dict(GOOD_PROTOCOLS, **{"TLSv1": "accepted", "TLSv1.1": "accepted"})
    findings = evaluate_transport(GOOD_INFO, protocols, GOOD_REDIRECT)
    legacy = by_id(findings, "TLS-LEGACY-ACCEPTED")
    assert legacy.severity is Severity.MEDIUM
    assert legacy.evidence["accepted"] == ["TLSv1", "TLSv1.1"]

    untestable = dict(GOOD_PROTOCOLS, **{"TLSv1": "untestable", "TLSv1.1": "untestable"})
    assert evaluate_transport(GOOD_INFO, untestable, GOOD_REDIRECT) == []

    no13 = dict(GOOD_PROTOCOLS, **{"TLSv1.3": "refused"})
    assert ids(evaluate_transport(GOOD_INFO, no13, GOOD_REDIRECT)) == {"TLS-NO-TLS13"}


def test_legacy_negotiated_and_weak_cipher():
    info = dict(GOOD_INFO, protocol="TLSv1", cipher="ECDHE-RSA-RC4-SHA")
    findings = evaluate_transport(info, GOOD_PROTOCOLS, GOOD_REDIRECT)
    assert {"TLS-LEGACY-NEGOTIATED", "TLS-WEAK-CIPHER"} <= ids(findings)


def test_http_redirect_cases():
    no_redirect = dict(GOOD_REDIRECT, status=200, location=None, to_https=False)
    findings = evaluate_transport(GOOD_INFO, GOOD_PROTOCOLS, no_redirect)
    assert ids(findings) == {"HTTP-NO-HTTPS-REDIRECT"}

    http_redirect = dict(GOOD_REDIRECT, status=302, location="http://www.example.test/home", to_https=False)
    assert ids(evaluate_transport(GOOD_INFO, GOOD_PROTOCOLS, http_redirect)) == {"HTTP-NO-HTTPS-REDIRECT"}

    closed = dict(GOOD_REDIRECT, status=None, location=None, to_https=None)
    assert evaluate_transport(GOOD_INFO, GOOD_PROTOCOLS, closed) == []

    assert evaluate_transport(GOOD_INFO, GOOD_PROTOCOLS, {"tested": False}) == []
