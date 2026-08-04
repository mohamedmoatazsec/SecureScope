import requests
from urllib.parse import urljoin


def scan_robots(url):
    robots_url = urljoin(url, "/robots.txt")

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
            robots_url,
            timeout=10,
            headers={
                "User-Agent": "SecureScope/1.0"
            },
        )

        result["status"] = response.status_code

        if response.status_code != 200:
            return result

        result["found"] = True

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if ":" not in line:
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

    except Exception as e:

        result["error"] = str(e)

        return result