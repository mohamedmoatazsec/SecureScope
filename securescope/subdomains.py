import socket
import requests
from urllib.parse import urlparse


COMMON_SUBDOMAINS = [
    "www",
    "api",
    "blog",
    "cdn",
    "static",
    "assets",
    "mail",
    "ftp",
    "dev",
    "staging",
]


def scan_subdomains(url):

    hostname = urlparse(url).hostname

    if not hostname:
        hostname = url

    results = []

    for sub in COMMON_SUBDOMAINS:

        target = f"{sub}.{hostname}"

        try:

            ip = socket.gethostbyname(target)

            try:

                response = requests.get(
                    f"https://{target}",
                    timeout=3,
                    allow_redirects=True,
                    verify=True,
                    headers={
                        "User-Agent": "SecureScope/1.0"
                    },
                )

                status = response.status_code

            except Exception:

                status = None

            results.append({
                "subdomain": target,
                "ip": ip,
                "status": status,
            })

        except socket.gaierror:
            pass

    return results