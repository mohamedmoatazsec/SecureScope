"""security.txt (RFC 9116) discovery and parsing."""

from urllib.parse import urljoin

import requests

from securescope import USER_AGENT

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]


def parse_security_txt(text):
    """Parse security.txt fields into {field: [values]}. Pure function."""
    fields = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip(), []).append(value.strip())
    return fields


def scan_securitytxt(url, timeout=10):
    """Look for a security.txt at the standard and legacy locations."""
    result = {
        "found": False,
        "location": None,
        "status": None,
        "fields": {},
    }

    for path in SECURITY_TXT_PATHS:
        target = urljoin(url, path)
        try:
            response = requests.get(
                target,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            result["error"] = str(exc)
            return result

        if response.status_code != 200:
            continue

        result["found"] = True
        result["location"] = target
        result["status"] = response.status_code
        result["fields"] = parse_security_txt(response.text)
        return result

    return result
