from securescope.headers import SECURITY_HEADERS
from securescope.recommendations import generate_recommendations


def _clean_results():
    return {
        "headers": {h: True for h in SECURITY_HEADERS},
        "cookies": [{"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"}],
        "tls": {"protocol": "TLSv1.3", "days": 200},
        "robots": {"found": True},
        "securitytxt": {"found": True},
        "methods": {"TRACE": {"status": 405, "allowed": False}},
        "cors": {"vulnerable": False, "reflected": False},
    }


def test_clean_target_produces_no_recommendations():
    assert generate_recommendations(_clean_results()) == []


def test_missing_headers_and_cookie_flags_are_reported():
    results = _clean_results()
    results["headers"]["Content-Security-Policy"] = False
    results["cookies"] = [{"name": "sid", "secure": False, "httponly": False, "samesite": None}]

    titles = [r["title"] for r in generate_recommendations(results)]

    assert "Missing Content-Security-Policy" in titles
    assert "Cookie 'sid' missing Secure flag" in titles
    assert "Cookie 'sid' missing HttpOnly flag" in titles
    assert "Cookie 'sid' without SameSite=Lax/Strict" in titles


def test_recommendations_are_sorted_by_severity():
    results = _clean_results()
    results["robots"] = {"found": False}  # LOW
    results["securitytxt"] = {"found": False}  # MEDIUM
    results["cors"] = {"vulnerable": True, "reflected": True, "finding": "Arbitrary origin reflected"}  # HIGH

    severities = [r["severity"] for r in generate_recommendations(results)]
    assert severities == ["HIGH", "MEDIUM", "LOW"]


def test_tls_expiry_and_legacy_protocol():
    results = _clean_results()
    results["tls"] = {"protocol": "TLSv1.1", "days": 10}
    titles = [r["title"] for r in generate_recommendations(results)]
    assert "Legacy TLS version negotiated" in titles
    assert "Certificate expiring within 30 days" in titles


def test_unreachable_target_does_not_crash():
    # scan_headers returns {} when the target cannot be fetched
    results = {"headers": {}, "cookies": [], "tls": {"error": "timeout"}}
    assert generate_recommendations(results) == []
