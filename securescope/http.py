"""HTTP plumbing: one configured session per scan, and a fetch helper.

Everything that talks to the target goes through here so proxying (for
example through Burp), custom headers for authenticated scans, timeouts,
retries and TLS verification are applied consistently.
"""

from __future__ import annotations

import warnings
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from securescope import USER_AGENT
from securescope.config import ScanConfig

try:  # urllib3 is a requests dependency; the import path moved between versions
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore[assignment]


class ScanSession:
    """A thin wrapper over requests.Session carrying the scan configuration."""

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.config.user_agent or USER_AGENT
        self.session.headers["Accept"] = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
        self.session.headers.update(self.config.headers)
        for name, value in self.config.cookies.items():
            self.session.cookies.set(name, value)
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        self.session.verify = self.config.verify_tls
        if not self.config.verify_tls:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

        if Retry is not None and self.config.retries > 0:
            retry = Retry(
                total=self.config.retries,
                backoff_factor=0.3,
                status_forcelist=(502, 503, 504),
                allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)
        # Passed per request on purpose: requests lets REQUESTS_CA_BUNDLE / HTTPS_PROXY from the
        # environment override Session-level settings, which would silently ignore --insecure
        # and --proxy. Explicit per-request values always win.
        kwargs.setdefault("verify", self.config.verify_tls)
        if self.config.proxy:
            kwargs.setdefault("proxies", {"http": self.config.proxy, "https": self.config.proxy})
        return self.session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> ScanSession:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def set_cookie_headers(response: requests.Response) -> list[str]:
    """Return every raw Set-Cookie header on a response, one entry per cookie.

    `response.headers` folds repeated headers into one comma-joined string,
    which breaks cookies whose Expires attribute contains a comma; the
    underlying urllib3 header dict keeps them separate.
    """
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "getlist"):
        values = headers.getlist("Set-Cookie")
        if values:
            return list(values)
    folded = response.headers.get("Set-Cookie")
    return split_folded_set_cookie(folded) if folded else []


def split_folded_set_cookie(value: str) -> list[str]:
    """Best-effort split of a comma-folded Set-Cookie header.

    Splits on ", " only when what follows looks like the start of a new
    cookie (`name=`), so "Expires=Wed, 21 Oct 2026" stays intact.
    """
    import re

    parts = re.split(r",\s*(?=[^\s;,=]+=)", value)
    return [p.strip() for p in parts if p.strip()]


def is_html(response: requests.Response) -> bool:
    content_type = response.headers.get("Content-Type", "")
    return "text/html" in content_type.lower() or "xhtml" in content_type.lower()
