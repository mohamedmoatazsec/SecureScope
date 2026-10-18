"""TLS and transport checks: certificate validity, protocol versions, HTTP redirect.

These checks open their own sockets to the target (they cannot go
through an HTTP proxy), which is also why the negotiated protocol and
cipher reflect what this client offers rather than a full server audit.
For a complete cipher-suite assessment use testssl.sh or sslyze; this
check is meant to catch the configuration mistakes that matter most.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any

import requests

from securescope.checks.base import Check, ScanContext
from securescope.findings import CheckResult, Confidence, Finding, Severity

REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "https://www.rfc-editor.org/rfc/rfc8996",
    "https://ssl-config.mozilla.org/",
]

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "ANON")


def _finding(
    id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    evidence: dict,
    confidence: Confidence = Confidence.CERTAIN,
    cwe: int | None = None,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        description=description,
        remediation=remediation,
        check="tls",
        confidence=confidence,
        evidence=evidence,
        references=list(REFERENCES),
        cwe=cwe,
    )


def _days(n: int) -> str:
    return "1 day" if abs(n) == 1 else f"{abs(n)} days"


def _parse_cert_time(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _decode_der(der: bytes) -> dict:
    """Decode a DER certificate into the dict shape getpeercert() uses.

    Only needed when verification failed (an unverified socket returns an
    empty dict). Uses a private but long-standing helper of the ssl module.
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        path = handle.name
    try:
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - platform specific
        return {}


def summarize_certificate(cert: dict, now: datetime | None = None) -> dict[str, Any]:
    """Pull the fields worth reporting out of a getpeercert()-style dict. Pure function."""
    now = now or datetime.now(timezone.utc)
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    subject = dict(item[0] for item in cert.get("subject", ()))
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    expires = _parse_cert_time(not_after) if not_after else None
    starts = _parse_cert_time(not_before) if not_before else None
    return {
        "subject": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "sans": sans,
        "not_before": starts.strftime("%Y-%m-%d") if starts else None,
        "not_after": expires.strftime("%Y-%m-%d") if expires else None,
        "days_remaining": (expires - now).days if expires else None,
        "serial": cert.get("serialNumber"),
    }


def connect(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    """Open a verified TLS connection and describe it; fall back to unverified on failure."""
    info: dict[str, Any] = {"verified": False, "verify_error": None, "certificate": {}}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["protocol"] = ssock.version()
                cipher = ssock.cipher()
                info["cipher"] = cipher[0] if cipher else None
                info["cipher_bits"] = cipher[2] if cipher else None
                info["certificate"] = summarize_certificate(ssock.getpeercert())
                info["verified"] = True
                return info
    except ssl.SSLCertVerificationError as exc:
        info["verify_error"] = exc.verify_message if hasattr(exc, "verify_message") else str(exc)
    except ssl.SSLError as exc:
        info["verify_error"] = str(exc)

    # Second attempt without verification so the report can still show the certificate.
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with insecure.wrap_socket(sock, server_hostname=hostname) as ssock:
            info["protocol"] = ssock.version()
            cipher = ssock.cipher()
            info["cipher"] = cipher[0] if cipher else None
            info["cipher_bits"] = cipher[2] if cipher else None
            der = ssock.getpeercert(binary_form=True)
            if der:
                info["certificate"] = summarize_certificate(_decode_der(der))
    return info


def probe_protocol(hostname: str, port: int, version: ssl.TLSVersion, timeout: float) -> str:
    """Return 'accepted', 'refused' or 'untestable' for one TLS protocol version."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return "accepted"
    except ssl.SSLError as exc:
        text = str(exc).upper()
        if "NO_PROTOCOLS_AVAILABLE" in text or "UNSUPPORTED_PROTOCOL" in text or "NO PROTOCOLS" in text:
            return "untestable"
        return "refused"
    except OSError:
        return "untestable"


def evaluate_transport(
    info: dict[str, Any], protocols: dict[str, str], redirect: dict[str, Any]
) -> list[Finding]:
    """Turn connection facts into findings. Pure function."""
    findings: list[Finding] = []
    cert = info.get("certificate") or {}

    if not info.get("verified"):
        findings.append(
            _finding(
                "TLS-CERT-UNTRUSTED",
                "TLS certificate failed validation",
                Severity.HIGH,
                f"The certificate could not be validated: {info.get('verify_error') or 'unknown error'}. "
                "Browsers show a full-page warning for this, which trains users to click through "
                "warnings, and it makes the connection trivially interceptable for anyone who does.",
                "Install a certificate from a trusted CA that covers this hostname, including the full "
                "intermediate chain.",
                {
                    "name": "certificate",
                    "error": info.get("verify_error"),
                    "subject": cert.get("subject"),
                    "sans": cert.get("sans"),
                },
                cwe=295,
            )
        )

    days = cert.get("days_remaining")
    if days is not None:
        if days < 0:
            findings.append(
                _finding(
                    "TLS-CERT-EXPIRED",
                    f"TLS certificate expired {_days(days)} ago",
                    Severity.HIGH,
                    "An expired certificate is rejected by browsers and API clients alike.",
                    "Renew the certificate and automate renewal (ACME) so it cannot lapse again.",
                    {"name": "certificate", "not_after": cert.get("not_after"), "days_remaining": days},
                    cwe=295,
                )
            )
        elif days <= 14:
            findings.append(
                _finding(
                    "TLS-CERT-EXPIRING",
                    f"TLS certificate expires in {_days(days)}",
                    Severity.MEDIUM,
                    "The certificate is about to expire. Once it does, every client rejects the connection.",
                    "Renew now and automate renewal.",
                    {"name": "certificate", "not_after": cert.get("not_after"), "days_remaining": days},
                )
            )
        elif days <= 30:
            findings.append(
                _finding(
                    "TLS-CERT-EXPIRING-SOON",
                    f"TLS certificate expires in {_days(days)}",
                    Severity.LOW,
                    "Renewal is due within the month.",
                    "Schedule the renewal, or automate it.",
                    {"name": "certificate", "not_after": cert.get("not_after"), "days_remaining": days},
                )
            )

    protocol = info.get("protocol")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            _finding(
                "TLS-LEGACY-NEGOTIATED",
                f"Server negotiated {protocol} with a modern client",
                Severity.HIGH,
                f"Offered TLS 1.2 and 1.3, the server still chose {protocol}, which is deprecated "
                "(RFC 8996) and has known weaknesses.",
                "Enable TLS 1.2 and 1.3 and disable everything older.",
                {"name": "protocol", "value": protocol},
                cwe=326,
            )
        )

    accepted = [
        name for name, state in protocols.items() if state == "accepted" and name in ("TLSv1", "TLSv1.1")
    ]
    if accepted:
        findings.append(
            _finding(
                "TLS-LEGACY-ACCEPTED",
                f"Server still accepts {', '.join(accepted)}",
                Severity.MEDIUM,
                "TLS 1.0 and 1.1 are deprecated by RFC 8996 and disabled in every current browser. "
                "Keeping them enabled allows downgrade attacks against old clients and fails most "
                "compliance baselines (PCI DSS requires 1.2+).",
                "Set the minimum protocol version to TLS 1.2.",
                {"name": "protocols", "accepted": accepted, "all": protocols},
                cwe=326,
            )
        )
    if protocols.get("TLSv1.3") == "refused" and protocols.get("TLSv1.2") == "accepted":
        findings.append(
            _finding(
                "TLS-NO-TLS13",
                "TLS 1.3 is not offered",
                Severity.INFO,
                "The server only speaks TLS 1.2. TLS 1.3 removes legacy cipher suites and renegotiation "
                "and is faster to handshake.",
                "Enable TLS 1.3 in the web server or load balancer configuration.",
                {"name": "protocols", "all": protocols},
            )
        )

    cipher = (info.get("cipher") or "").upper()
    if cipher and any(marker in cipher for marker in WEAK_CIPHER_MARKERS):
        findings.append(
            _finding(
                "TLS-WEAK-CIPHER",
                f"Weak cipher suite negotiated: {info.get('cipher')}",
                Severity.HIGH,
                "The negotiated cipher suite uses an algorithm with known practical attacks.",
                "Use the Mozilla 'intermediate' cipher list and disable RC4, 3DES, export and NULL suites.",
                {"name": "cipher", "value": info.get("cipher")},
                cwe=327,
            )
        )

    if redirect.get("tested"):
        if redirect.get("status") is None:
            pass  # port 80 closed or unreachable: nothing to downgrade to
        elif not redirect.get("to_https"):
            location = redirect.get("location")
            how = f"with a redirect to {location}" if location else "with content"
            findings.append(
                _finding(
                    "HTTP-NO-HTTPS-REDIRECT",
                    "Plain HTTP is served without redirecting to HTTPS",
                    Severity.MEDIUM,
                    f"http://{redirect.get('host')}/ answered {redirect.get('status')} {how} instead of "
                    "redirecting to the HTTPS site. Users who type the address or follow an old link stay on "
                    "an unencrypted connection.",
                    "Redirect every http:// request to the same URL on https:// with a 301, then send HSTS.",
                    {
                        "name": "http-redirect",
                        "status": redirect.get("status"),
                        "location": redirect.get("location"),
                    },
                    cwe=319,
                )
            )

    return findings


class TLSCheck(Check):
    id = "tls"
    name = "TLS and transport"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if not ctx.is_https:
            result.skipped = "target is not https://"
            result.findings = [
                self.finding(
                    ctx,
                    "HTTP-ONLY-TARGET",
                    "Target was scanned over plain HTTP",
                    Severity.INFO,
                    "The scan ran against an http:// URL, so transport security could not be assessed. "
                    "If the site is meant to be reachable over HTTPS, scan that URL as well.",
                    "Scan the https:// URL; serve the application over HTTPS only.",
                    references=list(REFERENCES),
                )
            ]
            return result

        timeout = ctx.config.timeout
        try:
            info = connect(ctx.hostname, ctx.port, timeout)
        except (OSError, ssl.SSLError, ValueError) as exc:
            result.error = f"TLS connection failed: {exc}"
            return result

        protocols = {}
        for label, version in (
            ("TLSv1", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ):
            protocols[label] = probe_protocol(ctx.hostname, ctx.port, version, min(timeout, 5.0))

        redirect: dict[str, Any] = {"tested": False, "host": ctx.hostname}
        if ctx.port == 443:
            redirect["tested"] = True
            try:
                response = ctx.session.get(
                    f"http://{ctx.hostname}/", allow_redirects=False, timeout=min(timeout, 8.0), limit=0
                )
                location = response.headers.get("Location")
                redirect.update(
                    status=response.status_code,
                    location=location,
                    to_https=bool(location and location.lower().startswith("https://")),
                )
            except requests.RequestException:
                redirect.update(status=None, location=None, to_https=None)

        result.findings = evaluate_transport(info, protocols, redirect)
        for finding in result.findings:
            finding.target = ctx.target
        result.facts = {**info, "protocols": protocols, "http_redirect": redirect}
        return result
