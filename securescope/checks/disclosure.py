"""Information disclosure through response headers.

Version strings in Server / X-Powered-By and friends do not cause a
breach on their own, but they hand an attacker the exact software and
version to look up, and every hardening baseline asks for them to be
removed. Rated low, reported with the exact value as evidence.
"""

from __future__ import annotations

import re

from securescope.checks.base import Check, ScanContext, header_map
from securescope.findings import CheckResult, Confidence, Finding, Severity

REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server",
    "https://cwe.mitre.org/data/definitions/200.html",
]

VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")

# Headers that exist only to announce the technology stack.
TECH_HEADERS = (
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-backend-server",
    "x-runtime",
    "x-version",
    "x-php-version",
)


def evaluate_disclosure(headers: dict[str, str]) -> list[Finding]:
    """`headers` is a lower-cased mapping. Pure function."""
    findings: list[Finding] = []

    server = headers.get("server")
    if server and VERSION_RE.search(server):
        findings.append(
            Finding(
                id="SERVER-VERSION-DISCLOSED",
                title=f"Server header reveals the software version ({server})",
                severity=Severity.LOW,
                description=(
                    "The Server header includes a version number. Attackers use it to pick exploits "
                    "that match the exact release, and scanners use it to prioritise targets."
                ),
                remediation=(
                    "Configure the server to send a product name without a version (ServerTokens Prod "
                    "in Apache, server_tokens off in nginx) or remove the header at the edge."
                ),
                check="disclosure",
                confidence=Confidence.FIRM,
                evidence={"name": "Server", "value": server},
                references=list(REFERENCES),
                cwe=200,
            )
        )

    for name in TECH_HEADERS:
        value = headers.get(name)
        if value is None:
            continue
        has_version = bool(VERSION_RE.search(value))
        findings.append(
            Finding(
                id="TECH-HEADER-DISCLOSED",
                title=f"{name} header reveals the technology stack",
                severity=Severity.LOW if has_version else Severity.INFO,
                description=(
                    f"The response includes {name}: {value}. The header serves no purpose for clients "
                    "and tells an attacker which framework"
                    + (" and version" if has_version else "")
                    + " to target."
                ),
                remediation=f"Remove the {name} header in the application or at the reverse proxy.",
                check="disclosure",
                confidence=Confidence.CERTAIN,
                evidence={"name": name, "value": value},
                references=list(REFERENCES),
                cwe=200,
            )
        )

    return findings


class DisclosureCheck(Check):
    id = "disclosure"
    name = "Information disclosure"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result
        headers = header_map(ctx.response.headers)
        result.findings = evaluate_disclosure(headers)
        for finding in result.findings:
            finding.target = ctx.target
        result.facts = {name: headers.get(name) for name in ("server", *TECH_HEADERS) if headers.get(name)}
        return result
