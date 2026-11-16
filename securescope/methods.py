"""HTTP method enumeration."""

import requests

from securescope import USER_AGENT

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]

# Status codes that mean "the server refuses this method": forbidden, not allowed, not implemented.
NOT_ALLOWED = (403, 405, 501)


def parse_allow_header(value):
    """Split an Allow header into a list of method names. Pure function."""
    if not value:
        return []
    return [item.strip().upper() for item in value.split(",") if item.strip()]


def scan_methods(url, timeout=5):
    """Probe each HTTP method against `url` and record how the server answers."""
    result = {}
    headers = {"User-Agent": USER_AGENT}

    for method in METHODS:
        try:
            response = requests.request(method, url, timeout=timeout, headers=headers, allow_redirects=False)
            result[method] = {
                "status": response.status_code,
                "allowed": response.status_code not in NOT_ALLOWED,
            }
        except requests.RequestException:
            result[method] = {"status": None, "allowed": False}

    try:
        options = requests.options(url, timeout=timeout, headers=headers)
        allowed = parse_allow_header(options.headers.get("Allow"))
        if allowed:
            result["Allow Header"] = allowed
    except requests.RequestException:
        pass

    return result
