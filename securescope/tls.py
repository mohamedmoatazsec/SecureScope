import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


def scan_tls(url):
    parsed = urlparse(url)

    hostname = parsed.hostname

    if hostname is None:
        hostname = url.replace("https://", "").replace("http://", "")

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cert = ssock.getpeercert()

                protocol = ssock.version()

                issuer = dict(x[0] for x in cert["issuer"])

                subject = dict(x[0] for x in cert["subject"])

                expires = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                remaining = (expires - datetime.utcnow()).days

                return {
                    "protocol": protocol,
                    "issuer": issuer.get("organizationName", ""),
                    "subject": subject.get("commonName", ""),
                    "expires": expires.strftime("%Y-%m-%d"),
                    "days": remaining,
                }

    except Exception as e:
        return {
            "error": str(e)
        }