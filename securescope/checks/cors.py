"""CORS policy review.

The check sends a request carrying a foreign Origin and reads the
Access-Control-* headers that come back. The combination that matters
is a foreign origin being allowed *with credentials*: that is what lets
a page on another site read authenticated responses. A wildcard with
credentials is flagged too, at a lower severity, because browsers
refuse that combination; it still shows the policy was not thought
through.
"""

from __future__ import annotations

from typing import Any

import requests

from securescope.checks.base import Check, ScanContext, header_map
from securescope.findings import CheckResult, Confidence, Finding, Severity

PROBE_ORIGIN = "https://securescope-probe.invalid"

REFERENCES = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    "https://portswigger.net/web-security/cors",
    "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
]


def analyze_cors(response_headers, sent_origin: str = PROBE_ORIGIN) -> dict[str, Any]:
    """Evaluate the CORS headers of one response. Pure function."""
    lowered = header_map(response_headers)

    def get(name: str) -> str | None:
        return lowered.get(name.lower())

    origin = get("Access-Control-Allow-Origin")
    credentials = get("Access-Control-Allow-Credentials")
    credentials_on = str(credentials).strip().lower() == "true"

    reflected = origin is not None and origin.strip() == sent_origin
    null_origin = origin is not None and origin.strip().lower() == "null"
    wildcard = origin is not None and origin.strip() == "*"

    return {
        "sent_origin": sent_origin,
        "origin": origin,
        "credentials": credentials,
        "credentials_on": credentials_on,
        "methods": get("Access-Control-Allow-Methods"),
        "headers": get("Access-Control-Allow-Headers"),
        "exposed_headers": get("Access-Control-Expose-Headers"),
        "max_age": get("Access-Control-Max-Age"),
        "vary": get("Vary"),
        "reflected": reflected,
        "null_origin": null_origin,
        "wildcard": wildcard,
    }


def evaluate_cors(probe: dict[str, Any], null_probe: dict[str, Any] | None = None) -> list[Finding]:
    """Turn the analysis of the probe responses into findings. Pure function."""
    findings: list[Finding] = []

    def add(id, title, severity, description, remediation, evidence, confidence=Confidence.FIRM, cwe=942):
        findings.append(
            Finding(
                id=id,
                title=title,
                severity=severity,
                description=description,
                remediation=remediation,
                check="cors",
                confidence=confidence,
                evidence=evidence,
                references=list(REFERENCES),
                cwe=cwe,
            )
        )

    evidence = {
        "name": "Access-Control-Allow-Origin",
        "sent_origin": probe.get("sent_origin"),
        "allow_origin": probe.get("origin"),
        "allow_credentials": probe.get("credentials"),
    }

    if probe.get("reflected") and probe.get("credentials_on"):
        add(
            "CORS-REFLECTED-CREDENTIALS",
            "Any origin is allowed to read authenticated responses",
            Severity.HIGH,
            "The server echoed an arbitrary Origin back in Access-Control-Allow-Origin and set "
            "Access-Control-Allow-Credentials: true. A page on any website can therefore make "
            "credentialed requests to this endpoint and read the responses, including whatever the "
            "logged-in user can see.",
            "Validate the Origin against an explicit allowlist of trusted origins and only then echo it; "
            "never reflect arbitrary origins when credentials are allowed. Add Vary: Origin.",
            evidence,
        )
    elif probe.get("reflected"):
        add(
            "CORS-REFLECTED",
            "Arbitrary origins are allowed (without credentials)",
            Severity.LOW,
            "The server reflects any Origin in Access-Control-Allow-Origin. Credentials are not allowed, "
            "so authenticated data is safe, but any site can read unauthenticated responses, and the "
            "policy breaks the moment someone enables credentials.",
            "Reflect only allowlisted origins, or use '*' deliberately for genuinely public resources.",
            evidence,
        )

    if null_probe and null_probe.get("null_origin") and null_probe.get("credentials_on"):
        add(
            "CORS-NULL-CREDENTIALS",
            "The 'null' origin is allowed with credentials",
            Severity.MEDIUM,
            "Access-Control-Allow-Origin: null with credentials enabled lets content running in a "
            "sandboxed iframe or from a local file, which browsers give the 'null' origin, read "
            "authenticated responses.",
            "Never allowlist 'null'. Use an explicit list of trusted origins.",
            {**evidence, "sent_origin": "null", "allow_origin": null_probe.get("origin")},
        )

    if probe.get("wildcard") and probe.get("credentials_on"):
        add(
            "CORS-WILDCARD-CREDENTIALS",
            "Wildcard origin combined with Access-Control-Allow-Credentials",
            Severity.LOW,
            "Browsers reject '*' together with credentials, so this is not exploitable as-is, but it "
            "shows the policy was not reviewed and a later change to origin reflection would be.",
            "Remove Access-Control-Allow-Credentials unless cross-origin credentialed access is required, "
            "and then replace '*' with an allowlist.",
            evidence,
            confidence=Confidence.CERTAIN,
        )

    if (
        probe.get("origin")
        and not probe.get("wildcard")
        and "origin" not in (probe.get("vary") or "").lower()
    ):
        add(
            "CORS-NO-VARY-ORIGIN",
            "Per-origin CORS response without Vary: Origin",
            Severity.INFO,
            "Access-Control-Allow-Origin varies by request but the response does not say Vary: Origin, "
            "so a shared cache can serve one origin's CORS headers to another.",
            "Add Vary: Origin to responses that set Access-Control-Allow-Origin dynamically.",
            {**evidence, "vary": probe.get("vary")},
            confidence=Confidence.CERTAIN,
            cwe=None,
        )

    return findings


class CORSCheck(Check):
    id = "cors"
    name = "CORS"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        try:
            response = ctx.session.get(ctx.target, headers={"Origin": PROBE_ORIGIN})
            probe = analyze_cors(response.headers, PROBE_ORIGIN)
            null_probe = None
            if probe.get("origin") is not None:
                null_response = ctx.session.get(ctx.target, headers={"Origin": "null"})
                null_probe = analyze_cors(null_response.headers, "null")
        except requests.RequestException as exc:
            result.error = str(exc)
            return result

        result.findings = evaluate_cors(probe, null_probe)
        for finding in result.findings:
            finding.target = ctx.target
        result.facts = {"probe": probe, "null_probe": null_probe}
        return result
