"""HTTP method review: what the server advertises, and whether TRACE is on.

The check only sends OPTIONS and TRACE. It deliberately does not send
PUT or DELETE to the target: a posture scan should never risk changing
state, and a method listed in Allow is a lead to verify by hand with
proper authorisation, not something to fire blindly at a root URL.
"""

from __future__ import annotations

from typing import Any

import requests

from securescope.checks.base import Check, ScanContext
from securescope.findings import CheckResult, Confidence, Finding, Severity

REFERENCES = [
    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#http-methods",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/TRACE",
]

RISKY_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")


def parse_allow_header(value: str | None) -> list[str]:
    """Split an Allow / Access-Control-Allow-Methods header into method names. Pure function."""
    if not value:
        return []
    seen: list[str] = []
    for item in value.split(","):
        method = item.strip().upper()
        if method and method not in seen:
            seen.append(method)
    return seen


def evaluate_methods(allowed: list[str], trace_status: int | None, trace_echoed: bool) -> list[Finding]:
    """Pure evaluation of the OPTIONS answer and the TRACE probe."""
    findings: list[Finding] = []

    if trace_status == 200 and trace_echoed:
        findings.append(
            Finding(
                id="TRACE-ENABLED",
                title="HTTP TRACE is enabled",
                severity=Severity.MEDIUM,
                description=(
                    "The server answers TRACE by echoing the request, headers included. Combined with "
                    "another weakness (an XSS, a permissive plugin) it can expose cookies and "
                    "authorisation headers that scripts normally cannot read. It has no legitimate use "
                    "on a production site."
                ),
                remediation=(
                    "Disable TRACE in the web server (e.g. TraceEnable off in Apache) or at the "
                    "load balancer."
                ),
                check="methods",
                confidence=Confidence.CERTAIN,
                evidence={"name": "TRACE", "status": trace_status},
                references=list(REFERENCES),
                cwe=693,
            )
        )

    risky = [m for m in allowed if m in RISKY_METHODS]
    if risky:
        findings.append(
            Finding(
                id="METHODS-RISKY-ADVERTISED",
                title=f"Allow header advertises {', '.join(risky)}",
                severity=Severity.INFO,
                description=(
                    "The server lists state-changing or diagnostic methods for this URL. That is normal "
                    "for an API, but every one of them must be covered by authentication and "
                    "authorisation checks; this scan does not test that."
                ),
                remediation=(
                    "Confirm each advertised method is intended for this resource and enforces "
                    "authorisation. Remove the ones that are not used."
                ),
                check="methods",
                confidence=Confidence.FIRM,
                evidence={"name": "Allow", "allowed": allowed, "risky": risky},
                references=list(REFERENCES),
            )
        )
    return findings


class MethodsCheck(Check):
    id = "methods"
    name = "HTTP methods"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        facts: dict[str, Any] = {"allowed": [], "options_status": None, "trace_status": None}

        try:
            options = ctx.session.request("OPTIONS", ctx.target, allow_redirects=False)
            facts["options_status"] = options.status_code
            allowed = parse_allow_header(options.headers.get("Allow")) or parse_allow_header(
                options.headers.get("Access-Control-Allow-Methods")
            )
            facts["allowed"] = allowed
        except requests.RequestException as exc:
            result.error = f"OPTIONS failed: {exc}"
            allowed = []

        trace_echoed = False
        try:
            marker = "X-SecureScope-Trace"
            trace = ctx.session.request("TRACE", ctx.target, headers={marker: "1"}, allow_redirects=False)
            facts["trace_status"] = trace.status_code
            body = trace.text[:4096] if trace.text else ""
            trace_echoed = marker.lower() in body.lower()
        except requests.RequestException as exc:
            facts["trace_error"] = str(exc)

        result.findings = evaluate_methods(allowed, facts["trace_status"], trace_echoed)
        for finding in result.findings:
            finding.target = ctx.target
        result.facts = facts
        return result
