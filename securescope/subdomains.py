"""Subdomain discovery using a small built-in wordlist."""

import socket

import requests

from securescope import USER_AGENT
from securescope.tls import hostname_from_url

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
    "admin",
    "test",
]


def scan_subdomains(url, wordlist=None, timeout=3):
    """Resolve common subdomains of the target and note which answer over HTTPS."""
    hostname = hostname_from_url(url)
    results = []

    for sub in wordlist or COMMON_SUBDOMAINS:
        target = f"{sub}.{hostname}"
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            continue

        try:
            response = requests.get(
                f"https://{target}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
            status = response.status_code
        except requests.RequestException:
            status = None

        results.append({"subdomain": target, "ip": ip, "status": status})

    return results
