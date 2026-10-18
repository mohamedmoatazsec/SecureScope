"""TLS certificate inspection."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def hostname_from_url(url):
    """Extract the host part of a URL, tolerating bare hostnames."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def scan_tls(url, timeout=5):
    """Connect to port 443 and summarise the presented certificate."""
    hostname = hostname_from_url(url)
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"error": str(exc)}

    issuer = dict(item[0] for item in cert.get("issuer", ()))
    subject = dict(item[0] for item in cert.get("subject", ()))

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    remaining = (expires - datetime.now(timezone.utc)).days

    return {
        "protocol": protocol,
        "issuer": issuer.get("organizationName", ""),
        "subject": subject.get("commonName", ""),
        "expires": expires.strftime("%Y-%m-%d"),
        "days": remaining,
    }
