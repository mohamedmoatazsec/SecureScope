"""Cookie attribute checks, read straight from the Set-Cookie headers.

Reading the raw headers (rather than a parsed cookie jar) keeps the
exact attributes the server sent, including the ones a jar would
normalise away, and lets the evidence quote the real header line.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from securescope.checks.base import Check, ScanContext
from securescope.findings import CheckResult, Confidence, Finding, Severity
from securescope.http import set_cookie_headers

REFERENCES = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
]

# Names that usually identify a session or auth token; issues on these are rated higher.
SESSION_HINTS = ("sess", "auth", "token", "jwt", "login", "sid", "csrf", "xsrf", "remember", "identity")


@dataclass
class Cookie:
    name: str
    value: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    max_age: str | None = None
    expires: str | None = None
    raw: str = ""
    attributes: dict[str, str | None] = field(default_factory=dict)

    @property
    def session_like(self) -> bool:
        lowered = self.name.lower()
        return any(hint in lowered for hint in SESSION_HINTS)


def parse_set_cookie(header: str) -> Cookie | None:
    """Parse one Set-Cookie header value. Returns None when it has no name=value pair."""
    parts = [p.strip() for p in header.split(";")]
    if not parts or not parts[0]:
        return None
    first = parts[0]
    if "=" not in first:
        return None
    name, _, value = first.partition("=")
    cookie = Cookie(name=name.strip(), value=value.strip(), raw=header)
    for attr in parts[1:]:
        if not attr:
            continue
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip() if val else None
        cookie.attributes[key] = val
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.httponly = True
        elif key == "samesite":
            cookie.samesite = val
        elif key == "domain":
            cookie.domain = val
        elif key == "path":
            cookie.path = val
        elif key == "max-age":
            cookie.max_age = val
        elif key == "expires":
            cookie.expires = val
    return cookie


def _redact(header: str, cookie: Cookie) -> str:
    """Quote the header line with the cookie value masked; values can be secrets."""
    if not cookie.value:
        return header
    masked = cookie.value[:3] + "…" if len(cookie.value) > 6 else "…"
    return header.replace(cookie.value, masked, 1)


def _finding(
    cookie: Cookie,
    id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    cwe: int | None = None,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        description=description,
        remediation=remediation,
        check="cookies",
        confidence=Confidence.CERTAIN,
        evidence={
            "name": cookie.name,
            "header": _redact(cookie.raw, cookie),
            "session_like": cookie.session_like,
        },
        references=list(REFERENCES),
        cwe=cwe,
    )


def evaluate_cookies(headers: list[str], is_https: bool) -> list[Finding]:
    """Evaluate every Set-Cookie header of one response. Pure function."""
    findings: list[Finding] = []
    for header in headers:
        cookie = parse_set_cookie(header)
        if cookie is None:
            continue
        bump = cookie.session_like

        if not cookie.secure and is_https:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-NO-SECURE",
                    f"Cookie '{cookie.name}' is set without the Secure attribute",
                    Severity.HIGH if bump else Severity.MEDIUM,
                    "The cookie will also be sent over plain HTTP, so anyone who can get the browser to "
                    "make an http:// request to the domain (a link, an image, a redirect) can read it "
                    "on the network.",
                    "Add the Secure attribute. For session cookies, also use the __Host- prefix.",
                    cwe=614,
                )
            )

        if not cookie.httponly:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-NO-HTTPONLY",
                    f"Cookie '{cookie.name}' is readable by JavaScript (no HttpOnly)",
                    Severity.MEDIUM if bump else Severity.LOW,
                    "Without HttpOnly, any script running on the page, including one injected through "
                    "XSS or a compromised third-party script, can read the cookie and send it elsewhere.",
                    "Add HttpOnly unless client-side code genuinely has to read this cookie.",
                    cwe=1004,
                )
            )

        samesite = (cookie.samesite or "").lower()
        if samesite == "none" and not cookie.secure:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-SAMESITE-NONE-INSECURE",
                    f"Cookie '{cookie.name}' has SameSite=None without Secure",
                    Severity.MEDIUM,
                    "Browsers reject SameSite=None cookies that are not also Secure, so this cookie is "
                    "silently dropped by modern browsers and sent cross-site by old ones.",
                    "Add Secure, or use SameSite=Lax if cross-site use is not required.",
                    cwe=1275,
                )
            )
        elif not samesite:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-NO-SAMESITE",
                    f"Cookie '{cookie.name}' has no SameSite attribute",
                    Severity.LOW,
                    "Without SameSite, cross-site request forgery protection depends on the browser's "
                    "default (Lax in Chromium-based browsers, nothing in some others).",
                    "Set SameSite=Lax (or Strict for cookies that never need to be sent on navigation).",
                    cwe=1275,
                )
            )

        if cookie.name.startswith("__Host-"):
            if not cookie.secure or cookie.domain is not None or cookie.path != "/":
                findings.append(
                    _finding(
                        cookie,
                        "COOKIE-HOST-PREFIX-INVALID",
                        f"Cookie '{cookie.name}' violates the __Host- prefix rules",
                        Severity.MEDIUM,
                        "A __Host- cookie must be Secure, have Path=/ and no Domain attribute, otherwise "
                        "browsers refuse to store it and the application silently loses the cookie.",
                        "Set Secure; Path=/ and remove the Domain attribute.",
                        cwe=1275,
                    )
                )
        elif cookie.name.startswith("__Secure-") and not cookie.secure:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-SECURE-PREFIX-INVALID",
                    f"Cookie '{cookie.name}' uses the __Secure- prefix without Secure",
                    Severity.MEDIUM,
                    "Browsers reject __Secure- cookies that lack the Secure attribute.",
                    "Add the Secure attribute.",
                    cwe=1275,
                )
            )

        if cookie.domain and cookie.domain.lstrip(".").count(".") == 1 and bump:
            findings.append(
                _finding(
                    cookie,
                    "COOKIE-BROAD-DOMAIN",
                    f"Session cookie '{cookie.name}' is scoped to the whole domain ({cookie.domain})",
                    Severity.LOW,
                    "A Domain attribute at the registrable-domain level sends the cookie to every "
                    "subdomain, so a weakness on any subdomain can expose or fixate the session.",
                    "Drop the Domain attribute so the cookie is host-only, or use the __Host- prefix.",
                    cwe=1275,
                )
            )

    return findings


class CookiesCheck(Check):
    id = "cookies"
    name = "Cookies"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result

        raw = set_cookie_headers(ctx.response)
        # Cookies set on redirects along the way count too; they belong to the same site.
        for hop in getattr(ctx.response, "history", []) or []:
            raw.extend(set_cookie_headers(hop))

        is_https = (ctx.response.url or ctx.target).lower().startswith("https://")
        result.findings = evaluate_cookies(raw, is_https=is_https)
        for finding in result.findings:
            finding.target = ctx.target

        parsed = [c for c in (parse_set_cookie(h) for h in raw) if c]
        result.facts = {
            "count": len(parsed),
            "cookies": [
                {
                    "name": c.name,
                    "secure": c.secure,
                    "httponly": c.httponly,
                    "samesite": c.samesite,
                    "domain": c.domain,
                    "path": c.path,
                }
                for c in parsed
            ],
        }
        return result
