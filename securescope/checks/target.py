"""What the target did when fetched: redirect chain, downgrades, refused hops, truncation.

Runs first so the report starts by saying which URL the rest of the
findings actually describe.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from securescope.checks.base import Check, ScanContext
from securescope.findings import CheckResult, Confidence, Severity

REFERENCES = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
]


class TargetCheck(Check):
    id = "target"
    name = "Target and redirects"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result

        final_url = ctx.response.url or ctx.target
        hops = list(ctx.hops)
        result.facts = {
            "final_url": final_url,
            "status": ctx.response.status_code,
            "redirects": hops,
            "redirect_blocked": ctx.redirect_blocked,
            "body_truncated": ctx.body_truncated,
        }

        if ctx.redirect_blocked:
            location = ctx.redirect_blocked["location"]
            reason = ctx.redirect_blocked["reason"]
            internal = "internal" in reason
            result.findings.append(
                self.finding(
                    ctx,
                    "REDIRECT-TO-INTERNAL-ADDRESS" if internal else "REDIRECT-NOT-FOLLOWED",
                    "Site redirects to an internal address"
                    if internal
                    else "Redirect chain was not followed",
                    Severity.LOW,
                    (
                        f"The target redirected to {location}, which is a loopback, link-local or private "
                        "address. Visitors cannot reach it, and it exposes internal naming or topology."
                        if internal
                        else f"The redirect to {location} was not followed: {reason}. Findings below "
                        "describe the last response that was received."
                    ),
                    "Point the redirect at the public hostname, or remove it.",
                    confidence=Confidence.CERTAIN,
                    evidence={"name": "Location", "location": location, "reason": reason},
                    references=REFERENCES,
                    cwe=200 if internal else None,
                )
            )

        for hop in hops:
            src = urlsplit(hop["url"])
            dst = urlsplit(hop["location"])
            if src.scheme == "https" and dst.scheme == "http":
                result.findings.append(
                    self.finding(
                        ctx,
                        "REDIRECT-HTTPS-TO-HTTP",
                        "HTTPS page redirects to plain HTTP",
                        Severity.MEDIUM,
                        f"{hop['url']} answered {hop['status']} with a redirect to {hop['location']}. "
                        "Anything after that hop travels unencrypted, and the browser's HTTPS indicator "
                        "is lost.",
                        "Redirect to the https:// version of the destination.",
                        confidence=Confidence.CERTAIN,
                        evidence={"name": "Location", "location": hop["location"], "status": hop["status"]},
                        references=REFERENCES,
                        cwe=319,
                    )
                )
                break

        origin_host = (urlsplit(ctx.target).hostname or "").lower()
        final_host = (urlsplit(final_url).hostname or "").lower()
        if hops and final_host and final_host != origin_host:
            result.findings.append(
                self.finding(
                    ctx,
                    "TARGET-REDIRECTED",
                    f"Target redirected to {final_host}",
                    Severity.INFO,
                    f"{ctx.target} redirected ({len(hops)} hop(s)) to {final_url}. The header, cookie and "
                    "content findings in this report describe the final response.",
                    "No action needed; scan the final URL directly if that is the application you meant.",
                    confidence=Confidence.CERTAIN,
                    evidence={"name": "Location", "location": final_url, "hops": len(hops)},
                    references=REFERENCES,
                )
            )

        if ctx.body_truncated:
            result.findings.append(
                self.finding(
                    ctx,
                    "RESPONSE-BODY-TRUNCATED",
                    "Response body was larger than the scanner's limit",
                    Severity.INFO,
                    "Only the first part of the response body was read. Header checks are unaffected; the "
                    "technology fingerprint may be incomplete.",
                    "No action needed.",
                    evidence={"name": "body", "location": final_url},
                    references=[],
                )
            )
        return result
