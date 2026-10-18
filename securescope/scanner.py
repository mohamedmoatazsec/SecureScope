"""Run every check against a target and assemble the result document."""

from securescope.cors import scan_cors
from securescope.dns import scan_dns
from securescope.headers import scan_headers
from securescope.methods import scan_methods
from securescope.portscan import scan_ports
from securescope.recommendations import generate_recommendations
from securescope.robots import scan_robots
from securescope.securitytxt import scan_securitytxt
from securescope.subdomains import scan_subdomains
from securescope.technologies import detect_technologies
from securescope.tls import scan_tls
from securescope.whois import scan_whois


def normalize_url(url):
    """Default to https:// when the user passes a bare hostname."""
    url = url.strip()
    if "://" not in url:
        url = f"https://{url}"
    return url


def scan(url, skip_ports=False, skip_subdomains=False):
    """Scan `url` and return a dict with one entry per check plus recommendations."""
    url = normalize_url(url)
    headers, cookies, headers_error = scan_headers(url)

    results = {
        "target": url,
        "headers": headers,
        "cookies": cookies,
        "tls": scan_tls(url),
        "dns": scan_dns(url),
        "ports": [] if skip_ports else scan_ports(url),
        "subdomains": [] if skip_subdomains else scan_subdomains(url),
        "technologies": detect_technologies(url),
        "robots": scan_robots(url),
        "securitytxt": scan_securitytxt(url),
        "whois": scan_whois(url),
        "methods": scan_methods(url),
        "cors": scan_cors(url),
    }

    if headers_error:
        results["errors"] = {"headers": headers_error}

    results["recommendations"] = generate_recommendations(results)
    return results
