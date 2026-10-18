"""HTTP plumbing: one configured session per scan, and a hardened fetch.

Everything that talks to the target goes through here so proxying (for
example through Burp), custom headers for authenticated scans, timeouts,
retries and TLS verification are applied consistently, and so the target
cannot hurt the scanner:

* response bodies are read up to a size limit, never fully into memory;
* redirects are followed by hand, at most MAX_REDIRECTS hops, and a public
  target is never allowed to redirect the scanner into loopback, link-local
  or private address space (a scanner running in CI would otherwise be a
  convenient way to reach cloud metadata endpoints or internal services).
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from securescope import USER_AGENT
from securescope.config import ScanConfig

try:  # urllib3 is a requests dependency; the import path moved between versions
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore[assignment]

BODY_LIMIT = 2 * 1024 * 1024  # bytes kept from any one response
MAX_REDIRECTS = 5
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def is_internal_host(host: str) -> bool:
    """True for loopback, link-local, private, reserved or unspecified addresses and localhost names.

    Only IP literals and `localhost` are classified; other names are not resolved here, so a
    name that resolves to an internal address is the operator's responsibility (and DNS
    rebinding is out of scope for a posture scanner).
    """
    host = (host or "").strip().strip("[]").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def read_body(response: requests.Response, limit: int = BODY_LIMIT) -> bool:
    """Read at most `limit` bytes of a streamed response into it. Returns True if truncated."""
    chunks: list[bytes] = []
    size = 0
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                truncated = True
                break
    finally:
        response.close()
    data = b"".join(chunks)[:limit]
    response._content = data  # type: ignore[attr-defined]  # makes .content/.text work on a closed stream
    response._content_consumed = True  # type: ignore[attr-defined]
    response.securescope_truncated = truncated  # type: ignore[attr-defined]
    return truncated


class RedirectBlocked(requests.RequestException):
    """Raised when a redirect would take the scanner somewhere it must not go."""

    def __init__(self, message: str, location: str, response: requests.Response):
        super().__init__(message, response=response)
        self.location = location


class ScanSession:
    """A thin wrapper over requests.Session carrying the scan configuration."""

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.session = requests.Session()
        self.session.max_redirects = MAX_REDIRECTS
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

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("stream", True)
        kwargs["allow_redirects"] = False
        # Passed per request on purpose: requests lets REQUESTS_CA_BUNDLE / HTTPS_PROXY from the
        # environment override Session-level settings, which would silently ignore --insecure
        # and --proxy. Explicit per-request values always win.
        kwargs.setdefault("verify", self.config.verify_tls)
        if self.config.proxy:
            kwargs.setdefault("proxies", {"http": self.config.proxy, "https": self.config.proxy})
        return self.session.request(method, url, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        limit: int = BODY_LIMIT,
        max_redirects: int = MAX_REDIRECTS,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a request, follow redirects by hand with the safety rules, and cap the body.

        The returned response has `history` set to the redirect hops it went through, plus
        `securescope_hops` (list of {url, status, location}) and `securescope_truncated`.
        Raises RedirectBlocked when a redirect is refused.
        """
        origin_host = urlsplit(url).hostname or ""
        hops: list[dict[str, Any]] = []
        history: list[requests.Response] = []
        current = url

        while True:
            response = self._request(method, current, **kwargs)
            location = response.headers.get("Location")
            if not allow_redirects or response.status_code not in REDIRECT_STATUSES or not location:
                break

            next_url = urljoin(current, location.strip())
            parts = urlsplit(next_url)
            hops.append({"url": current, "status": response.status_code, "location": next_url})
            response.close()
            history.append(response)

            if parts.scheme not in ("http", "https"):
                raise RedirectBlocked(f"redirect to unsupported scheme {parts.scheme!r}", next_url, response)
            if is_internal_host(parts.hostname or "") and not is_internal_host(origin_host):
                raise RedirectBlocked(
                    "redirect into an internal address was not followed", next_url, response
                )
            if len(hops) >= max_redirects:
                raise RedirectBlocked(f"more than {max_redirects} redirects", next_url, response)

            if response.status_code in (301, 302, 303) and method not in ("GET", "HEAD"):
                method = "GET"
                kwargs.pop("data", None)
                kwargs.pop("json", None)
            current = next_url

        read_body(response, limit)
        response.history = history
        response.securescope_hops = hops  # type: ignore[attr-defined]
        return response

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
    parts = re.split(r",\s*(?=[^\s;,=]+=)", value)
    return [p.strip() for p in parts if p.strip()]


def is_html(response: requests.Response) -> bool:
    content_type = response.headers.get("Content-Type", "")
    return "text/html" in content_type.lower() or "xhtml" in content_type.lower()
