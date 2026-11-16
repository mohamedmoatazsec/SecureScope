"""Lightweight technology fingerprinting from response headers and markup."""

INTERESTING_HEADERS = ["Server", "X-Powered-By", "CF-RAY", "CF-Cache-Status"]

# (needle in the lowercased Server header, technology name)
SERVER_SIGNATURES = [
    ("github.com", "GitHub"),
    ("cloudflare", "Cloudflare"),
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("microsoft-iis", "Microsoft IIS"),
    ("litespeed", "LiteSpeed"),
    ("openresty", "OpenResty"),
]

# (needle in the lowercased HTML, technology name)
HTML_SIGNATURES = [
    ("bootstrap", "Bootstrap"),
    ("jquery", "jQuery"),
    ("wp-content", "WordPress"),
    ("react", "React"),
]


def fingerprint(headers, html):
    """Derive technologies from a header mapping and page HTML. Pure function."""
    result = {"headers": {}, "technologies": []}

    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in INTERESTING_HEADERS:
        if name.lower() in lowered:
            result["headers"][name] = lowered[name.lower()]

    server = str(lowered.get("server", "")).lower()
    powered = str(lowered.get("x-powered-by", ""))
    html = (html or "").lower()

    for needle, tech in SERVER_SIGNATURES:
        if needle in server:
            result["technologies"].append((tech, "HIGH"))

    if powered:
        result["technologies"].append((powered, "HIGH"))

    for needle, tech in HTML_SIGNATURES:
        if needle in html:
            result["technologies"].append((tech, "MEDIUM"))

    # Preserve order, drop duplicates.
    result["technologies"] = list(dict.fromkeys(result["technologies"]))
    return result
