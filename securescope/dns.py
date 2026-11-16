"""DNS resolution."""

import socket

from securescope.tls import hostname_from_url


def scan_dns(url):
    """Resolve the target hostname to its IPv4 and IPv6 addresses."""
    hostname = hostname_from_url(url)
    result = {"hostname": hostname, "ipv4": [], "ipv6": []}

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        result["error"] = str(exc)
        return result

    ipv4, ipv6 = set(), set()
    for address in addresses:
        ip = address[4][0]
        (ipv6 if ":" in ip else ipv4).add(ip)

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)
    return result
