"""Scan configuration shared by the CLI, the scanner and the checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Default to https:// for bare hostnames and strip trailing whitespace.

    Keeps the path and query the user gave (an authenticated scan may need
    a specific page), and normalises an empty path to "/".
    """
    url = url.strip()
    if not url:
        raise ValueError("empty target")
    if "://" not in url:
        url = f"https://{url}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parts.scheme!r} in {url!r} (use http:// or https://)")
    if not parts.hostname:
        raise ValueError(f"no hostname in {url!r}")
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def hostname_from_url(url: str) -> str:
    """Extract the host part of a URL, tolerating bare hostnames."""
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def parse_header_option(value: str) -> tuple[str, str]:
    """Turn "Name: value" (as passed to -H) into a (name, value) pair."""
    if ":" not in value:
        raise ValueError(f"header {value!r} must look like 'Name: value'")
    name, _, raw = value.partition(":")
    name = name.strip()
    if not name:
        raise ValueError(f"header {value!r} has an empty name")
    return name, raw.strip()


@dataclass
class ScanConfig:
    timeout: float = 10.0
    retries: int = 1
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    user_agent: str | None = None
    verify_tls: bool = True
    checks: list[str] | None = None  # None = all checks
    skip_checks: list[str] = field(default_factory=list)
    ports: bool = False
    subdomains: bool = False
    whois: bool = False

    def wants(self, check_id: str) -> bool:
        if check_id in self.skip_checks:
            return False
        if self.checks is None:
            return True
        return check_id in self.checks
