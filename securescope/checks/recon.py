"""Reconnaissance checks: mostly facts for the report, a few low-severity findings.

robots.txt, security.txt, technology fingerprinting and DNS run by
default because they are a handful of harmless requests. WHOIS,
subdomain resolution and the port probe are opt-in (--whois,
--subdomains, --ports) since they are slower and noisier.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

from securescope.checks.base import Check, ScanContext
from securescope.dns import scan_dns
from securescope.findings import CheckResult, Confidence, Severity
from securescope.portscan import scan_ports
from securescope.robots import parse_robots
from securescope.securitytxt import SECURITY_TXT_PATHS, parse_security_txt
from securescope.subdomains import scan_subdomains
from securescope.technologies import fingerprint
from securescope.whois import scan_whois

SECURITY_TXT_REFS = ["https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/"]

# Ports that should essentially never be reachable from the internet on a web host.
SENSITIVE_PORTS = {
    21: "FTP (cleartext credentials)",
    23: "Telnet (cleartext)",
    110: "POP3 (cleartext)",
    143: "IMAP (cleartext)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
}


class RobotsCheck(Check):
    id = "robots"
    name = "robots.txt"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        try:
            response = ctx.session.get(urljoin(ctx.origin + "/", "robots.txt"))
        except requests.RequestException as exc:
            result.error = str(exc)
            return result
        found = response.status_code == 200 and "html" not in response.headers.get("Content-Type", "").lower()
        result.facts = {"found": found, "status": response.status_code}
        if found:
            result.facts.update(parse_robots(response.text))
        return result


class SecurityTxtCheck(Check):
    id = "securitytxt"
    name = "security.txt"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        result.facts = {"found": False, "location": None, "fields": {}}
        for path in SECURITY_TXT_PATHS:
            url = urljoin(ctx.origin + "/", path.lstrip("/"))
            try:
                response = ctx.session.get(url)
            except requests.RequestException as exc:
                result.error = str(exc)
                return result
            if response.status_code != 200 or "html" in response.headers.get("Content-Type", "").lower():
                continue
            fields = parse_security_txt(response.text)
            if not fields.get("Contact"):
                continue
            result.facts = {"found": True, "location": url, "fields": fields}
            break

        if not result.facts["found"]:
            result.findings.append(
                self.finding(
                    ctx,
                    "SECURITY-TXT-MISSING",
                    "No security.txt (RFC 9116)",
                    Severity.LOW,
                    "There is no /.well-known/security.txt, so a researcher who finds a vulnerability "
                    "has no sanctioned way to report it and may give up or disclose publicly instead.",
                    "Publish /.well-known/security.txt with at least Contact: and Expires: fields "
                    "(generate one at securitytxt.org).",
                    evidence={"name": "security.txt", "location": "/.well-known/security.txt"},
                    references=SECURITY_TXT_REFS,
                )
            )
            return result

        fields = result.facts["fields"]
        expires = (fields.get("Expires") or [None])[0]
        if expires:
            try:
                when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if when < datetime.now(timezone.utc):
                    result.findings.append(
                        self.finding(
                            ctx,
                            "SECURITY-TXT-EXPIRED",
                            "security.txt has expired",
                            Severity.LOW,
                            f"The Expires field ({expires}) is in the past. RFC 9116 says an expired file "
                            "must not be trusted, so researchers may ignore the contact details.",
                            "Update the Expires field (at most a year ahead) and refresh the file regularly.",
                            evidence={
                                "name": "security.txt",
                                "expires": expires,
                                "location": result.facts["location"],
                            },
                            references=SECURITY_TXT_REFS,
                        )
                    )
            except ValueError:
                pass
        else:
            result.findings.append(
                self.finding(
                    ctx,
                    "SECURITY-TXT-NO-EXPIRES",
                    "security.txt is missing the required Expires field",
                    Severity.INFO,
                    "RFC 9116 requires Expires so readers know whether the contact details are current.",
                    "Add an Expires: field in ISO 8601 format.",
                    evidence={"name": "security.txt", "location": result.facts["location"]},
                    references=SECURITY_TXT_REFS,
                )
            )
        return result


class TechnologyCheck(Check):
    id = "technologies"
    name = "Technology fingerprint"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if ctx.response is None:
            result.skipped = ctx.fetch_error or "no response from target"
            return result
        result.facts = fingerprint(ctx.response.headers, ctx.response.text)
        return result


class DNSCheck(Check):
    id = "dns"
    name = "DNS"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        facts = scan_dns(ctx.target)
        if "error" in facts:
            result.error = facts.pop("error")
        result.facts = facts
        return result


class WhoisCheck(Check):
    id = "whois"
    name = "WHOIS"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if not ctx.config.whois:
            result.skipped = "pass --whois to enable"
            return result
        facts = scan_whois(ctx.target)
        if "error" in facts:
            result.error = facts.pop("error")
        result.facts = facts
        return result


class SubdomainsCheck(Check):
    id = "subdomains"
    name = "Subdomains"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if not ctx.config.subdomains:
            result.skipped = "pass --subdomains to enable"
            return result
        result.facts = {"found": scan_subdomains(ctx.target, timeout=min(ctx.config.timeout, 5))}
        return result


class PortsCheck(Check):
    id = "ports"
    name = "Open ports"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        if not ctx.config.ports:
            result.skipped = "pass --ports to enable"
            return result
        open_ports = scan_ports(ctx.target)
        result.facts = {"open": open_ports}
        seen = set()
        for entry in open_ports:
            port = entry["port"]
            if port in SENSITIVE_PORTS and port not in seen:
                seen.add(port)
                result.findings.append(
                    self.finding(
                        ctx,
                        "PORT-SENSITIVE-SERVICE",
                        f"{SENSITIVE_PORTS[port]} is reachable on port {port}",
                        Severity.MEDIUM,
                        f"A TCP connection to port {port} on {entry['ip']} succeeded. Services like this "
                        "should not be reachable from the internet on a web host; if they are, they are "
                        "exposed to credential attacks and known exploits.",
                        "Bind the service to localhost or a private network, and restrict the port with a "
                        "firewall or security group.",
                        confidence=Confidence.FIRM,
                        evidence={"name": str(port), "ip": entry["ip"], "service": entry["service"]},
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html"
                        ],
                        cwe=284,
                    )
                )
        return result
