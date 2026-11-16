"""Content-Security-Policy parsing and evaluation.

The evaluator applies the hardening rules that browser vendors and OWASP
publish for CSP: scripts must be restricted, inline and eval must not be
allowed without nonces/hashes, plugins and base URIs should be locked
down, and a policy that is only in report-only mode protects nobody.
It is a pure module: `evaluate_csp` takes header values and returns
findings without touching the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from securescope.checks.base import Check, ScanContext, header_map
from securescope.findings import CheckResult, Confidence, Finding, Severity

CSP_HEADER = "Content-Security-Policy"
CSP_RO_HEADER = "Content-Security-Policy-Report-Only"

REFERENCES = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "https://csp-evaluator.withgoogle.com/",
]

KNOWN_DIRECTIVES = {
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "font-src",
    "connect-src",
    "media-src",
    "object-src",
    "child-src",
    "frame-src",
    "worker-src",
    "manifest-src",
    "prefetch-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "navigate-to",
    "sandbox",
    "report-uri",
    "report-to",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for",
    "trusted-types",
    "plugin-types",
    "referrer",
}

BROAD_SCHEMES = {"*", "http:", "https:", "data:", "blob:", "filesystem:"}


@dataclass
class Policy:
    raw: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    duplicates: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    def get(self, name: str) -> list[str] | None:
        return self.directives.get(name)

    def effective(self, name: str) -> list[str] | None:
        """A fetch directive falls back to default-src when absent."""
        if name in self.directives:
            return self.directives[name]
        return self.directives.get("default-src")


def parse_csp(value: str) -> Policy:
    """Parse a CSP header value into directives. Later duplicates are ignored, as browsers do."""
    policy = Policy(raw=value)
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        tokens = chunk.split()
        name = tokens[0].lower()
        sources = tokens[1:]
        if name in policy.directives:
            policy.duplicates.append(name)
            continue
        if name not in KNOWN_DIRECTIVES:
            policy.unknown.append(name)
        policy.directives[name] = sources
    return policy


def _lower(sources: list[str]) -> list[str]:
    return [s.lower() for s in sources]


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in _lower(sources))


def _excerpt(value: str, limit: int = 400) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


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
        check="csp",
        confidence=confidence,
        evidence=evidence,
        references=list(REFERENCES),
        cwe=cwe,
    )


def evaluate_csp(enforced: str | None, report_only: str | None = None, is_html: bool = True) -> list[Finding]:
    """Evaluate the enforced and report-only CSP headers of one response."""
    findings: list[Finding] = []

    if not enforced:
        if report_only:
            findings.append(
                _finding(
                    "CSP-REPORT-ONLY",
                    "Content-Security-Policy is report-only",
                    Severity.MEDIUM,
                    "Only a Content-Security-Policy-Report-Only header is sent. Violations are reported but "
                    "nothing is blocked, so the policy offers no protection against injected scripts.",
                    "Once the report-only policy is clean in production, ship the same policy in an "
                    "enforcing Content-Security-Policy header.",
                    {"name": CSP_RO_HEADER, "value": _excerpt(report_only)},
                    cwe=693,
                )
            )
        else:
            findings.append(
                _finding(
                    "CSP-MISSING",
                    "No Content-Security-Policy",
                    Severity.HIGH if is_html else Severity.LOW,
                    "The response carries no Content-Security-Policy header. Without one, any injected "
                    "script (XSS) runs with the full privileges of the page, and there is no defence in "
                    "depth against markup injection, clickjacking or data exfiltration.",
                    "Deploy a nonce- or hash-based policy, for example: "
                    "default-src 'self'; script-src 'nonce-<random>' 'strict-dynamic'; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'. Start in report-only mode, then enforce.",
                    {"name": CSP_HEADER, "value": None, "html": is_html},
                    cwe=693,
                )
            )
        return findings

    policy = parse_csp(enforced)
    evidence_base = {"name": CSP_HEADER, "value": _excerpt(enforced)}

    for name in policy.unknown:
        findings.append(
            _finding(
                "CSP-UNKNOWN-DIRECTIVE",
                f"Unknown CSP directive '{name}'",
                Severity.LOW,
                f"The directive '{name}' is not a CSP directive, so browsers ignore it. This is usually a "
                "typo or a stray separator, which can silently leave part of the policy unapplied.",
                "Fix the directive name; check the policy with a CSP validator before deploying.",
                {**evidence_base, "directive": name},
            )
        )
    for name in sorted(set(policy.duplicates)):
        findings.append(
            _finding(
                "CSP-DUPLICATE-DIRECTIVE",
                f"Duplicate CSP directive '{name}'",
                Severity.LOW,
                f"'{name}' appears more than once. Browsers keep the first occurrence and ignore the rest, "
                "so the later values are not applied.",
                "Merge the duplicate directives into one.",
                {**evidence_base, "directive": name},
            )
        )

    script = policy.effective("script-src")
    if script is None:
        findings.append(
            _finding(
                "CSP-NO-SCRIPT-RESTRICTION",
                "CSP does not restrict script sources",
                Severity.HIGH,
                "Neither script-src nor default-src is set, so the policy places no restriction on where "
                "scripts may load from or whether inline scripts run. For XSS defence this is equivalent "
                "to having no policy.",
                "Add a script-src directive (or a restrictive default-src) using nonces or hashes "
                "with 'strict-dynamic'.",
                evidence_base,
                cwe=693,
            )
        )
        script = []

    lowered = _lower(script)
    source_directive = "script-src" if "script-src" in policy.directives else "default-src"
    has_nonce_or_hash = _has_nonce_or_hash(script)
    strict_dynamic = "'strict-dynamic'" in lowered

    if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
        findings.append(
            _finding(
                "CSP-UNSAFE-INLINE",
                "CSP allows inline scripts ('unsafe-inline')",
                Severity.HIGH,
                f"{source_directive} contains 'unsafe-inline' without a nonce or hash, so inline <script> "
                "blocks and event handlers are allowed. That is exactly what an XSS payload needs, so the "
                "policy does not mitigate script injection.",
                "Remove 'unsafe-inline' from script sources. Move inline scripts to files, or allow them "
                "individually with a per-response nonce ('nonce-…') or a hash ('sha256-…').",
                {**evidence_base, "directive": source_directive},
                cwe=79,
            )
        )
    elif "'unsafe-inline'" in lowered and has_nonce_or_hash:
        findings.append(
            _finding(
                "CSP-UNSAFE-INLINE-FALLBACK",
                "'unsafe-inline' kept as a fallback next to nonces/hashes",
                Severity.INFO,
                "Browsers that support nonces or hashes ignore 'unsafe-inline' when one is present, so "
                "modern browsers are protected. Legacy browsers without nonce support fall back to "
                "allowing all inline scripts.",
                "Fine as a compatibility fallback; remove it once legacy browser support is not needed.",
                {**evidence_base, "directive": source_directive},
            )
        )

    if "'unsafe-eval'" in lowered:
        findings.append(
            _finding(
                "CSP-UNSAFE-EVAL",
                "CSP allows eval() ('unsafe-eval')",
                Severity.MEDIUM,
                f"{source_directive} contains 'unsafe-eval', so eval(), new Function() and string "
                "arguments to setTimeout/setInterval are allowed. Code that reaches eval with attacker "
                "input becomes exploitable, and the policy cannot stop it.",
                "Remove 'unsafe-eval'. Replace eval-based templating or JSON parsing with safe "
                "alternatives (JSON.parse, precompiled templates).",
                {**evidence_base, "directive": source_directive},
                cwe=95,
            )
        )

    if not strict_dynamic:
        broad = [s for s in lowered if s in BROAD_SCHEMES]
        if broad:
            findings.append(
                _finding(
                    "CSP-BROAD-SCRIPT-SOURCE",
                    f"CSP script sources include {', '.join(sorted(set(broad)))}",
                    Severity.HIGH,
                    f"{source_directive} allows scripts from a wildcard or a whole scheme "
                    f"({', '.join(sorted(set(broad)))}). An attacker who can inject markup can load a script "
                    "from any matching URL, so the allowlist provides little protection.",
                    "Allow specific script origins only, or better, use a nonce/hash policy with "
                    "'strict-dynamic' so host allowlists are not needed.",
                    {**evidence_base, "directive": source_directive, "sources": sorted(set(broad))},
                    cwe=693,
                )
            )
        wildcard_hosts = [s for s in lowered if s.startswith("*.") or "://*." in s]
        if wildcard_hosts:
            findings.append(
                _finding(
                    "CSP-WILDCARD-HOST",
                    "CSP script allowlist contains wildcard hosts",
                    Severity.LOW,
                    f"{source_directive} allows scripts from wildcard hosts ({', '.join(wildcard_hosts)}). "
                    "Every subdomain of those domains, including ones that host user content, becomes a "
                    "valid script source.",
                    "Replace wildcard hosts with the exact origins that serve scripts, or move to a "
                    "nonce-based policy.",
                    {**evidence_base, "directive": source_directive, "sources": wildcard_hosts},
                )
            )

    default = _lower(policy.get("default-src") or [])
    default_is_none = default == ["'none'"]
    if policy.get("object-src") is None and not default_is_none:
        findings.append(
            _finding(
                "CSP-OBJECT-SRC",
                "CSP does not restrict plugins (object-src)",
                Severity.MEDIUM,
                "object-src is not set and default-src is not 'none', so <object>/<embed> content can be "
                "loaded. Legacy plugin content is another route to script execution.",
                "Add object-src 'none' (or set default-src 'none' and allow what you need explicitly).",
                {**evidence_base, "directive": "object-src"},
                cwe=693,
            )
        )

    if policy.get("base-uri") is None:
        findings.append(
            _finding(
                "CSP-BASE-URI",
                "CSP does not restrict <base> (base-uri)",
                Severity.LOW,
                "base-uri is not set. An injected <base href> tag can redirect every relative script and "
                "form URL on the page to an attacker-controlled origin.",
                "Add base-uri 'none' or base-uri 'self'.",
                {**evidence_base, "directive": "base-uri"},
                cwe=693,
            )
        )

    if policy.get("form-action") is None:
        findings.append(
            _finding(
                "CSP-FORM-ACTION",
                "CSP does not restrict form targets (form-action)",
                Severity.INFO,
                "form-action is not set, so injected markup can submit forms (including credentials) to "
                "any origin.",
                "Add form-action 'self' (plus any payment or SSO endpoints the site really posts to).",
                {**evidence_base, "directive": "form-action"},
            )
        )

    if policy.get("report-uri") is None and policy.get("report-to") is None:
        findings.append(
            _finding(
                "CSP-NO-REPORTING",
                "CSP violations are not reported anywhere",
                Severity.INFO,
                "Neither report-to nor report-uri is set, so blocked resources and attempted injections "
                "are never seen by the team.",
                "Add a report-to endpoint so violations (and attacks) are logged.",
                {**evidence_base, "directive": "report-to"},
            )
        )

    return findings


class CSPCheck(Check):
    id = "csp"
    name = "Content Security Policy"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result

        headers = header_map(ctx.response.headers)
        enforced = headers.get(CSP_HEADER.lower())
        report_only = headers.get(CSP_RO_HEADER.lower())
        content_type = headers.get("content-type", "")
        is_html = "html" in content_type.lower()

        result.findings = evaluate_csp(enforced, report_only, is_html=is_html)
        for finding in result.findings:
            finding.target = ctx.target

        result.facts = {
            "enforced": enforced,
            "report_only": report_only,
            "directives": parse_csp(enforced).directives if enforced else {},
        }
        return result
