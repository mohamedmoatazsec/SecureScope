"""Security response headers: present, and configured so they actually help.

Each header is evaluated on its value, not just its presence. A
Strict-Transport-Security with a ten-minute max-age or an
X-Frame-Options: ALLOW-FROM both "exist" and both fail.
"""

from __future__ import annotations

import re

from securescope.checks.base import Check, ScanContext, header_map
from securescope.checks.csp import parse_csp
from securescope.findings import CheckResult, Confidence, Finding, Severity

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"

ONE_YEAR = 31536000
SIX_MONTHS = 15552000

GOOD_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
WEAK_REFERRER_POLICIES = {
    "unsafe-url",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
}


def _finding(
    id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: dict,
    references: list[str],
    cwe: int | None = None,
    confidence: Confidence = Confidence.CERTAIN,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        description=description,
        remediation=remediation,
        check="headers",
        confidence=confidence,
        evidence=evidence,
        references=references,
        cwe=cwe,
    )


def parse_hsts(value: str) -> dict:
    """Parse a Strict-Transport-Security value into its directives."""
    result = {"max_age": None, "include_subdomains": False, "preload": False}
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age"):
            match = re.search(r"max-age\s*=\s*\"?(\d+)", part)
            if match:
                result["max_age"] = int(match.group(1))
        elif part == "includesubdomains":
            result["include_subdomains"] = True
        elif part == "preload":
            result["preload"] = True
    return result


def evaluate_hsts(value: str | None, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    refs = [MDN + "Strict-Transport-Security", "https://hstspreload.org/"]
    if not is_https:
        return findings  # browsers ignore HSTS over plain HTTP; the TLS check covers the redirect
    if value is None:
        findings.append(
            _finding(
                "HSTS-MISSING",
                "No Strict-Transport-Security header",
                Severity.HIGH,
                "The site is served over HTTPS but does not send Strict-Transport-Security, so a browser "
                "that is sent to the http:// URL (a typed address, an old link, a captive portal) makes an "
                "unencrypted request first. An attacker on the network can intercept that request and "
                "keep the victim on HTTP.",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload once "
                "every subdomain is HTTPS-only and submit the domain to hstspreload.org).",
                {"name": "Strict-Transport-Security", "value": None},
                refs,
                cwe=319,
            )
        )
        return findings

    parsed = parse_hsts(value)
    evidence = {"name": "Strict-Transport-Security", "value": value, **parsed}
    if parsed["max_age"] is None:
        findings.append(
            _finding(
                "HSTS-INVALID",
                "Strict-Transport-Security has no valid max-age",
                Severity.HIGH,
                "The header is present but has no parsable max-age directive, so browsers ignore it "
                "entirely.",
                "Set max-age=31536000; includeSubDomains.",
                evidence,
                refs,
                cwe=319,
            )
        )
        return findings
    if parsed["max_age"] == 0:
        findings.append(
            _finding(
                "HSTS-DISABLED",
                "Strict-Transport-Security max-age=0 disables HSTS",
                Severity.HIGH,
                "max-age=0 tells browsers to forget the HSTS policy, which is the opposite of protection.",
                "Set max-age=31536000; includeSubDomains.",
                evidence,
                refs,
                cwe=319,
            )
        )
        return findings
    if parsed["max_age"] < SIX_MONTHS:
        findings.append(
            _finding(
                "HSTS-SHORT-MAX-AGE",
                f"Strict-Transport-Security max-age is only {parsed['max_age']} seconds",
                Severity.MEDIUM,
                "A short max-age means the HTTPS-only policy expires soon after the last visit, leaving "
                "returning users exposed to the same downgrade attack HSTS exists to stop. Browsers "
                "require at least one year for preloading.",
                "Raise max-age to at least 31536000 (one year).",
                evidence,
                refs,
                cwe=319,
            )
        )
    if not parsed["include_subdomains"]:
        findings.append(
            _finding(
                "HSTS-NO-SUBDOMAINS",
                "Strict-Transport-Security does not cover subdomains",
                Severity.LOW,
                "Without includeSubDomains, cookies scoped to the parent domain can still be sent over "
                "plain HTTP to a subdomain, and subdomains remain open to downgrade attacks.",
                "Add includeSubDomains once every subdomain supports HTTPS.",
                evidence,
                refs,
                cwe=319,
            )
        )
    return findings


def evaluate_headers(headers: dict[str, str], is_https: bool, is_html: bool) -> list[Finding]:
    """Evaluate every security header except CSP (see csp.py) and cookies (see cookies.py).

    `headers` must be a lower-cased mapping (see header_map).
    """
    findings: list[Finding] = []
    findings.extend(evaluate_hsts(headers.get("strict-transport-security"), is_https))

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        findings.append(
            _finding(
                "XCTO-MISSING" if xcto is None else "XCTO-INVALID",
                "X-Content-Type-Options is not 'nosniff'",
                Severity.LOW,
                "Without X-Content-Type-Options: nosniff, some browsers guess the content type of "
                "responses and may execute a user-uploaded file or a misconfigured response as script "
                "or a stylesheet.",
                "Send X-Content-Type-Options: nosniff on every response.",
                {"name": "X-Content-Type-Options", "value": xcto},
                [MDN + "X-Content-Type-Options", OWASP_HEADERS],
                cwe=16,
            )
        )

    # Clickjacking: frame-ancestors wins over X-Frame-Options
    csp = headers.get("content-security-policy")
    frame_ancestors = parse_csp(csp).get("frame-ancestors") if csp else None
    xfo = headers.get("x-frame-options")
    if is_html:
        if frame_ancestors is None and xfo is None:
            findings.append(
                _finding(
                    "CLICKJACKING-UNPROTECTED",
                    "Page can be framed by any site (no frame-ancestors or X-Frame-Options)",
                    Severity.MEDIUM,
                    "Nothing stops another origin from loading this page in an iframe, which enables "
                    "clickjacking: overlaying the page so a user clicks buttons they cannot see.",
                    "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), and "
                    "X-Frame-Options: DENY for older browsers.",
                    {"name": "X-Frame-Options", "value": None, "frame_ancestors": None},
                    [MDN + "X-Frame-Options", "https://owasp.org/www-community/attacks/Clickjacking"],
                    cwe=1021,
                )
            )
        elif frame_ancestors is None and xfo is not None:
            value = xfo.strip().upper()
            if value.startswith("ALLOW-FROM") or value not in ("DENY", "SAMEORIGIN"):
                findings.append(
                    _finding(
                        "XFO-INVALID",
                        f"X-Frame-Options value '{xfo.strip()}' is not enforced by browsers",
                        Severity.MEDIUM,
                        "Only DENY and SAMEORIGIN are supported. ALLOW-FROM was never implemented by "
                        "Chrome or Safari and is ignored, and unknown values are ignored everywhere, so "
                        "the page is framable.",
                        "Use Content-Security-Policy: frame-ancestors, which supports an allowlist, and "
                        "set X-Frame-Options to DENY or SAMEORIGIN.",
                        {"name": "X-Frame-Options", "value": xfo},
                        [MDN + "X-Frame-Options"],
                        cwe=1021,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "XFO-ONLY",
                        "Clickjacking protection relies on X-Frame-Options alone",
                        Severity.INFO,
                        "X-Frame-Options works, but it is a legacy header with no allowlist support. "
                        "frame-ancestors is the standard replacement and takes precedence when both are set.",
                        "Add Content-Security-Policy: frame-ancestors 'none' (or 'self') alongside it.",
                        {"name": "X-Frame-Options", "value": xfo},
                        [MDN + "X-Frame-Options"],
                    )
                )
        elif frame_ancestors is not None and any(s == "*" for s in frame_ancestors):
            findings.append(
                _finding(
                    "FRAME-ANCESTORS-WILDCARD",
                    "frame-ancestors allows every origin (*)",
                    Severity.MEDIUM,
                    "frame-ancestors * permits any site to frame the page, which leaves it open to "
                    "clickjacking exactly as if the directive were absent.",
                    "Restrict frame-ancestors to 'none', 'self' or the specific origins that need to "
                    "embed the page.",
                    {"name": "Content-Security-Policy", "frame_ancestors": frame_ancestors},
                    [MDN + "Content-Security-Policy/frame-ancestors"],
                    cwe=1021,
                )
            )

    # Referrer-Policy
    referrer = headers.get("referrer-policy")
    if referrer is None:
        findings.append(
            _finding(
                "REFERRER-POLICY-MISSING",
                "No Referrer-Policy header",
                Severity.LOW,
                "Without a Referrer-Policy the browser default applies (strict-origin-when-cross-origin "
                "in modern browsers, but full URLs in older ones). Paths and query strings, which often "
                "carry tokens or identifiers, can leak to third parties.",
                "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive apps).",
                {"name": "Referrer-Policy", "value": None},
                [MDN + "Referrer-Policy"],
                cwe=200,
            )
        )
    else:
        # The last recognised token wins when several are listed.
        tokens = [t.strip().lower() for t in referrer.split(",") if t.strip()]
        chosen = next(
            (t for t in reversed(tokens) if t in GOOD_REFERRER_POLICIES | WEAK_REFERRER_POLICIES), None
        )
        if chosen in WEAK_REFERRER_POLICIES:
            findings.append(
                _finding(
                    "REFERRER-POLICY-WEAK",
                    f"Referrer-Policy '{chosen}' leaks URLs to other origins",
                    Severity.LOW,
                    "This policy sends the full URL (or the origin for downgrades) to cross-origin "
                    "destinations, so query strings and paths can end up in third-party logs.",
                    "Use strict-origin-when-cross-origin, same-origin or no-referrer.",
                    {"name": "Referrer-Policy", "value": referrer},
                    [MDN + "Referrer-Policy"],
                    cwe=200,
                )
            )

    # Permissions-Policy
    if is_html and headers.get("permissions-policy") is None:
        findings.append(
            _finding(
                "PERMISSIONS-POLICY-MISSING",
                "No Permissions-Policy header",
                Severity.LOW,
                "Browser features such as camera, microphone, geolocation and payment are available to "
                "the page and to any embedded third-party frame unless a Permissions-Policy turns them off.",
                "Send a Permissions-Policy that disables what the site does not use, e.g. "
                "camera=(), microphone=(), geolocation=(), payment=().",
                {"name": "Permissions-Policy", "value": None},
                [MDN + "Permissions-Policy"],
            )
        )

    # X-XSS-Protection is deprecated and can introduce side channels in old browsers.
    xss = headers.get("x-xss-protection")
    if xss is not None and xss.strip().startswith("1"):
        findings.append(
            _finding(
                "XSS-PROTECTION-LEGACY",
                "X-XSS-Protection: 1 enables a removed, exploitable filter",
                Severity.LOW,
                "The XSS auditor this header controls was removed from every modern browser; in the old "
                "browsers that still honour it, the filter itself has been used to leak page content. "
                "A real CSP is the replacement.",
                "Send X-XSS-Protection: 0, or drop the header, and rely on Content-Security-Policy.",
                {"name": "X-XSS-Protection", "value": xss},
                [MDN + "X-XSS-Protection"],
            )
        )

    # Cross-origin isolation headers (informational hardening)
    if is_html and headers.get("cross-origin-opener-policy") is None:
        findings.append(
            _finding(
                "COOP-MISSING",
                "No Cross-Origin-Opener-Policy header",
                Severity.INFO,
                "Without COOP, a page opened via window.open keeps a reference to this page's window, "
                "which is a building block for cross-window attacks and some side channels.",
                "Send Cross-Origin-Opener-Policy: same-origin unless the site relies on cross-origin popups.",
                {"name": "Cross-Origin-Opener-Policy", "value": None},
                [MDN + "Cross-Origin-Opener-Policy"],
            )
        )

    # Cache-Control on HTML: sensitive pages should not be cached by shared caches.
    cache = headers.get("cache-control")
    if is_html and cache is not None and "public" in cache.lower() and "no-store" not in cache.lower():
        findings.append(
            _finding(
                "CACHE-PUBLIC-HTML",
                "HTML response is marked Cache-Control: public",
                Severity.INFO,
                "The page is explicitly cacheable by shared caches. If any variant of it is personalised "
                "or authenticated, a proxy or CDN may serve one user's page to another.",
                "Use Cache-Control: no-store (or private) for authenticated or personalised pages.",
                {"name": "Cache-Control", "value": cache},
                [MDN + "Cache-Control"],
                cwe=525,
                confidence=Confidence.TENTATIVE,
            )
        )

    return findings


class HeadersCheck(Check):
    id = "headers"
    name = "Security headers"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result

        headers = header_map(ctx.response.headers)
        is_html = "html" in headers.get("content-type", "").lower()
        final_url = ctx.response.url or ctx.target
        is_https = final_url.lower().startswith("https://")

        result.findings = evaluate_headers(headers, is_https=is_https, is_html=is_html)
        for finding in result.findings:
            finding.target = ctx.target

        watched = [
            "strict-transport-security",
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
            "cache-control",
            "x-xss-protection",
        ]
        result.facts = {
            "status": ctx.response.status_code,
            "final_url": final_url,
            "content_type": headers.get("content-type"),
            "headers": {name: headers.get(name) for name in watched},
        }
        return result
