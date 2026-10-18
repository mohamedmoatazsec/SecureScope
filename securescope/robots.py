"""robots.txt discovery and parsing."""

from urllib.parse import urljoin

import requests

from securescope import USER_AGENT


def parse_robots(text):
    """Parse robots.txt content into its rule groups. Pure function."""
    result = {
        "disallow": [],
        "allow": [],
        "sitemaps": [],
        "crawl_delay": None,
        "hosts": [],
    }

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "disallow":
            result["disallow"].append(value)
        elif key == "allow":
            result["allow"].append(value)
        elif key == "sitemap":
            result["sitemaps"].append(value)
        elif key == "crawl-delay":
            result["crawl_delay"] = value
        elif key == "host":
            result["hosts"].append(value)

    return result


def scan_robots(url, timeout=10):
    """Fetch and parse /robots.txt for the site hosting `url`."""
    result = {
        "found": False,
        "status": None,
        "disallow": [],
        "allow": [],
        "sitemaps": [],
        "crawl_delay": None,
        "hosts": [],
    }

    try:
        response = requests.get(
            urljoin(url, "/robots.txt"),
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as exc:
        result["error"] = str(exc)
        return result

    result["status"] = response.status_code
    if response.status_code != 200:
        return result

    result["found"] = True
    result.update(parse_robots(response.text))
    return result
