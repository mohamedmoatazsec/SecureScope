def generate_recommendations(results):

    recommendations = []

    # ---------------- Security Headers ----------------

    headers = results.get("headers", {})

    required_headers = {
        "Content-Security-Policy":
            ("HIGH", "Add a strong Content-Security-Policy header."),

        "Strict-Transport-Security":
            ("HIGH", "Enable HTTP Strict Transport Security (HSTS)."),

        "X-Frame-Options":
            ("MEDIUM", "Protect against clickjacking using X-Frame-Options."),

        "X-Content-Type-Options":
            ("MEDIUM", "Enable X-Content-Type-Options: nosniff."),

        "Referrer-Policy":
            ("LOW", "Add a Referrer-Policy header."),

        "Permissions-Policy":
            ("HIGH", "Restrict browser features using Permissions-Policy."),
    }

    for header, (severity, advice) in required_headers.items():

        if not headers.get(header, False):

            recommendations.append({
                "severity": severity,
                "title": f"Missing {header}",
                "recommendation": advice,
            })

    # ---------------- Cookies ----------------

    cookies = results.get("cookies", [])

    for cookie in cookies:

        if not cookie.get("secure"):

            recommendations.append({
                "severity": "HIGH",
                "title": f"Cookie '{cookie['name']}' Missing Secure Flag",
                "recommendation":
                    "Mark sensitive cookies with the Secure attribute.",
            })

        if not cookie.get("httponly"):

            recommendations.append({
                "severity": "MEDIUM",
                "title": f"Cookie '{cookie['name']}' Missing HttpOnly",
                "recommendation":
                    "Use the HttpOnly attribute to reduce XSS risk.",
            })

    # ---------------- TLS ----------------

    tls = results.get("tls", {})

    if tls:

        protocol = tls.get("protocol", "")

        if protocol in ("TLSv1", "TLSv1.1"):

            recommendations.append({
                "severity": "HIGH",
                "title": "Legacy TLS Version",
                "recommendation":
                    "Upgrade to TLS 1.2 or TLS 1.3.",
            })

        days = tls.get("days", 999)

        if days < 30:

            recommendations.append({
                "severity": "HIGH",
                "title": "Certificate Expiring Soon",
                "recommendation":
                    "Renew the TLS certificate before it expires.",
            })

        elif days < 90:

            recommendations.append({
                "severity": "MEDIUM",
                "title": "Certificate Near Expiration",
                "recommendation":
                    "Plan certificate renewal.",
            })

    # ---------------- robots.txt ----------------

    robots = results.get("robots", {})

    if robots and not robots.get("found"):

        recommendations.append({
            "severity": "LOW",
            "title": "robots.txt Missing",
            "recommendation":
                "Consider adding a robots.txt file.",
        })

    # ---------------- security.txt ----------------

    security = results.get("securitytxt", {})

    if security and not security.get("found"):

        recommendations.append({
            "severity": "MEDIUM",
            "title": "security.txt Missing",
            "recommendation":
                "Publish /.well-known/security.txt to help security researchers.",
        })

    # ---------------- HTTP Methods ----------------

    methods = results.get("methods", {})

    if methods.get("TRACE", {}).get("allowed"):

        recommendations.append({
            "severity": "MEDIUM",
            "title": "TRACE Method Enabled",
            "recommendation":
                "Disable the TRACE HTTP method.",
        })

    # ---------------- CORS ----------------

    cors = results.get("cors", {})

    if cors.get("vulnerable"):

        recommendations.append({
            "severity": "HIGH",
            "title": "Potential CORS Misconfiguration",
            "recommendation":
                "Avoid using wildcard origins together with credentials.",
        })

    return recommendations