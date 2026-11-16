from http.cookiejar import CookieJar
from unittest import mock

import requests

from securescope.headers import SECURITY_HEADERS, evaluate_headers, extract_cookies, scan_headers


def test_all_headers_present_in_any_case():
    headers = {h.upper(): "x" for h in SECURITY_HEADERS}
    result = evaluate_headers(headers)
    assert result == {h: True for h in SECURITY_HEADERS}


def test_missing_headers_are_reported_false():
    result = evaluate_headers({"Content-Security-Policy": "default-src 'self'"})
    assert result["Content-Security-Policy"] is True
    assert result["Strict-Transport-Security"] is False
    assert len(result) == len(SECURITY_HEADERS)


def _jar_from_set_cookie(*set_cookie_values):
    response = requests.Response()
    response.status_code = 200
    response.url = "https://example.test/"
    response.headers = requests.structures.CaseInsensitiveDict()
    response.raw = mock.Mock()
    response.raw._original_response = mock.Mock()
    response.raw._original_response.msg = mock.Mock()
    response.raw._original_response.msg.get_all = lambda name, default=None: list(set_cookie_values)
    jar = CookieJar()
    req = requests.Request("GET", "https://example.test/").prepare()
    requests.cookies.extract_cookies_to_jar(jar, req, response.raw)
    return jar


def test_cookie_flags_are_detected():
    jar = _jar_from_set_cookie(
        "session=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
        "tracker=1; Path=/",
    )
    cookies = {c["name"]: c for c in extract_cookies(jar)}

    assert cookies["session"]["secure"] is True
    assert cookies["session"]["httponly"] is True
    assert cookies["session"]["samesite"] == "Strict"

    assert cookies["tracker"]["secure"] is False
    assert cookies["tracker"]["httponly"] is False
    assert cookies["tracker"]["samesite"] is None


def test_scan_headers_returns_empty_results_on_network_error():
    with mock.patch("securescope.headers.requests.get", side_effect=requests.ConnectionError("boom")):
        headers, cookies, error = scan_headers("https://example.test")
    assert headers == {}
    assert cookies == []
    assert "boom" in error
