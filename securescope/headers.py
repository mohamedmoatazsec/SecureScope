"""HTTP security header and cookie attribute checks."""

import requests

from securescope import USER_AGENT

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def evaluate_headers(response_headers):
    """Return {header_name: present} for each header in SECURITY_HEADERS.

    `response_headers` is any case-insensitive mapping (requests' headers
    object or a plain dict with the canonical names).
    """
    lowered = {str(k).lower(): v for k, v in response_headers.items()}
    return {header: header.lower() in lowered for header in SECURITY_HEADERS}


def _cookie_has_flag(cookie, flag):
    """True if the cookie carries `flag` (e.g. 'HttpOnly'), case-insensitively."""
    try:
        if cookie.has_nonstandard_attr(flag):
            return True
    except AttributeError:
        pass
    rest = getattr(cookie, "_rest", {}) or {}
    return any(str(key).lower() == flag.lower() for key in rest)


def _cookie_attr(cookie, name):
    rest = getattr(cookie, "_rest", {}) or {}
    for key, value in rest.items():
        if str(key).lower() == name.lower():
            return value
    return None


def extract_cookies(cookiejar):
    """Summarise the security attributes of every cookie in a CookieJar."""
    cookies = []
    for cookie in cookiejar:
        cookies.append(
            {
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": _cookie_has_flag(cookie, "HttpOnly"),
                "samesite": _cookie_attr(cookie, "SameSite"),
            }
        )
    return cookies


def scan_headers(url, timeout=10):
    """Fetch `url` and evaluate its security headers and cookies.

    Returns a tuple (headers, cookies, error). On a network failure
    `headers` is an empty dict, `cookies` an empty list and `error` the
    exception message, so callers never have to special-case None.
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as exc:
        return {}, [], str(exc)

    return evaluate_headers(response.headers), extract_cookies(response.cookies), None
