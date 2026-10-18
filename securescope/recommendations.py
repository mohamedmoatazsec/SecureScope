"""Turn raw scan results into prioritised, actionable recommendations."""

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        "HIGH",
        "Add a Content-Security-Policy that restricts script sources; avoid 'unsafe-inline'.",
    ),
    "Strict-Transport-Security": (
        "HIGH",
        "Enable HSTS (max-age of at least one year, includeSubDomains) so browsers never fall back to HTTP.",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "Send X-Frame-Options: DENY (or a CSP frame-ancestors directive) to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "Send X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    ),
    "Referrer-Policy": (
        "LOW",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "LOW",
        "Use Permissions-Policy to disable browser features the site does not need "
        "(camera, geolocation, ...).",
    ),
}


def _rec(severity, title, recommendation):
    return {"severity": severity, "title": title, "recommendation": recommendation}


def generate_recommendations(results):
    """Build the recommendation list from a full scan result. Pure function."""
    recommendations = []

    # Security headers
    headers = results.get("headers") or {}
    for header, (severity, advice) in REQUIRED_HEADERS.items():
        if headers and not headers.get(header, False):
            recommendations.append(_rec(severity, f"Missing {header}", advice))

    # Cookies
    for cookie in results.get("cookies") or []:
        name = cookie.get("name", "?")
        if not cookie.get("secure"):
            recommendations.append(
                _rec(
                    "HIGH",
                    f"Cookie '{name}' missing Secure flag",
                    "Set the Secure attribute so the cookie is only sent over HTTPS.",
                )
            )
        if not cookie.get("httponly"):
            recommendations.append(
                _rec(
                    "MEDIUM",
                    f"Cookie '{name}' missing HttpOnly flag",
                    "Set HttpOnly so scripts cannot read the cookie after an XSS.",
                )
            )
        samesite = (cookie.get("samesite") or "").lower()
        if samesite not in ("lax", "strict"):
            recommendations.append(
                _rec(
                    "LOW",
                    f"Cookie '{name}' without SameSite=Lax/Strict",
                    "Set SameSite=Lax (or Strict) to limit cross-site request forgery.",
                )
            )

    # TLS
    tls = results.get("tls") or {}
    if tls and "error" not in tls:
        if tls.get("protocol") in ("TLSv1", "TLSv1.1"):
            recommendations.append(
                _rec(
                    "HIGH",
                    "Legacy TLS version negotiated",
                    "Disable TLS 1.0/1.1; offer TLS 1.2 and 1.3 only.",
                )
            )
        days = tls.get("days", 999)
        if days < 30:
            recommendations.append(
                _rec("HIGH", "Certificate expiring within 30 days", "Renew the TLS certificate now.")
            )
        elif days < 90:
            recommendations.append(
                _rec("MEDIUM", "Certificate expiring within 90 days", "Schedule the certificate renewal.")
            )

    # robots.txt / security.txt
    robots = results.get("robots") or {}
    if robots and not robots.get("found"):
        recommendations.append(
            _rec("LOW", "robots.txt missing", "Publish a robots.txt so crawlers get explicit guidance.")
        )

    security = results.get("securitytxt") or {}
    if security and not security.get("found"):
        recommendations.append(
            _rec(
                "MEDIUM",
                "security.txt missing",
                "Publish /.well-known/security.txt (RFC 9116) so researchers know how to report issues.",
            )
        )

    # HTTP methods
    methods = results.get("methods") or {}
    if methods.get("TRACE", {}).get("allowed"):
        recommendations.append(
            _rec("MEDIUM", "TRACE method enabled", "Disable TRACE to rule out cross-site tracing.")
        )

    # CORS
    cors = results.get("cors") or {}
    if cors.get("vulnerable"):
        recommendations.append(
            _rec(
                "HIGH",
                f"CORS misconfiguration: {cors.get('finding')}",
                "Only allow an explicit list of trusted origins; never reflect the request Origin "
                "when credentials are enabled.",
            )
        )
    elif cors.get("reflected"):
        recommendations.append(
            _rec(
                "LOW",
                "CORS reflects arbitrary origins",
                "Restrict Access-Control-Allow-Origin to known origins even without credentials.",
            )
        )

    recommendations.sort(key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))
    return recommendations
