"""robots.txt parsing."""


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
