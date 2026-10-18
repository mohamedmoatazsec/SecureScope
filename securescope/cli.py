"""Command-line interface for SecureScope."""

import argparse
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from securescope import __version__
from securescope.report_csv import generate_csv_report
from securescope.report_html import generate_html_report
from securescope.report_json import generate_json_report
from securescope.scanner import normalize_url, scan

console = Console()

PASS = "[green]PASS[/green]"
FAIL = "[red]FAIL[/red]"


def banner():
    console.print(
        Panel.fit(
            f"[bold cyan]SecureScope[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[green]Web security posture assessment toolkit[/green]",
            border_style="cyan",
        )
    )


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(
        prog="securescope",
        description="Assess the security posture of a web application you are authorised to test.",
    )
    parser.add_argument("url", help="Target URL or hostname (https:// is assumed if omitted)")
    parser.add_argument("--html", action="store_true", help="write an HTML report")
    parser.add_argument("--json", action="store_true", help="write a JSON report")
    parser.add_argument("--csv", action="store_true", help="write a CSV report")
    parser.add_argument(
        "-o",
        "--output",
        default=".",
        metavar="DIR",
        help="directory for report files (default: current directory)",
    )
    parser.add_argument("--skip-ports", action="store_true", help="skip the TCP port scan")
    parser.add_argument("--skip-subdomains", action="store_true", help="skip subdomain discovery")
    parser.add_argument("--version", action="version", version=f"SecureScope {__version__}")
    return parser.parse_args(argv)


def show_headers(headers, error=None):
    table = Table(title="HTTP Security Headers")
    table.add_column("Header", style="cyan")
    table.add_column("Status", justify="center")

    if not headers:
        console.print(f"[red]Could not fetch the target:[/red] {error or 'no response'}")
        return

    score = 0
    for header, present in headers.items():
        table.add_row(header, PASS if present else FAIL)
        score += int(bool(present))

    console.print(table)

    percent = int(score / len(headers) * 100)
    color = "green" if percent >= 80 else "yellow" if percent >= 60 else "red"
    console.print(f"\nHeader score: [{color}]{percent}%[/{color}]")


def show_cookies(cookies):
    if not cookies:
        return
    table = Table(title="Cookies")
    table.add_column("Cookie", style="cyan")
    table.add_column("Secure", justify="center")
    table.add_column("HttpOnly", justify="center")
    table.add_column("SameSite", justify="center")
    for cookie in cookies:
        table.add_row(
            cookie["name"],
            PASS if cookie["secure"] else FAIL,
            PASS if cookie["httponly"] else FAIL,
            cookie.get("samesite") or "[red]-[/red]",
        )
    console.print(table)


def show_tls(tls):
    if not tls or "error" in tls:
        console.print(f"[yellow]TLS:[/yellow] {tls.get('error', 'not available')}")
        return
    table = Table(title="TLS Certificate")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Protocol", str(tls["protocol"]))
    table.add_row("Issuer", str(tls["issuer"]))
    table.add_row("Subject", str(tls["subject"]))
    table.add_row("Expires", str(tls["expires"]))
    table.add_row("Days remaining", str(tls["days"]))
    console.print(table)


def show_dns(dns):
    table = Table(title="DNS")
    table.add_column("Type", style="cyan")
    table.add_column("Value")
    for ip in dns.get("ipv4", []):
        table.add_row("IPv4", ip)
    for ip in dns.get("ipv6", []):
        table.add_row("IPv6", ip)
    if "error" in dns:
        table.add_row("Error", dns["error"])
    console.print(table)


def show_ports(ports):
    if not ports:
        return
    table = Table(title="Open Ports")
    table.add_column("IP")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Status")
    for port in ports:
        table.add_row(port["ip"], str(port["port"]), port["service"], port["status"])
    console.print(table)


def show_subdomains(subdomains):
    if not subdomains:
        return
    table = Table(title="Subdomains")
    table.add_column("Subdomain")
    table.add_column("IP")
    table.add_column("HTTPS status")
    for sub in subdomains:
        table.add_row(sub["subdomain"], sub["ip"], str(sub["status"]) if sub["status"] else "-")
    console.print(table)


def show_technologies(technologies):
    table = Table(title="Detected Technologies")
    table.add_column("Technology")
    table.add_column("Confidence")
    techs = technologies.get("technologies", [])
    if techs:
        for tech, confidence in techs:
            table.add_row(str(tech), str(confidence))
    else:
        table.add_row("No technologies detected", "-")
    console.print(table)


def show_robots(robots):
    table = Table(title="robots.txt")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Found", "YES" if robots.get("found") else "NO")
    table.add_row("HTTP status", str(robots.get("status")))
    table.add_row("Disallow rules", str(len(robots.get("disallow", []))))
    table.add_row("Allow rules", str(len(robots.get("allow", []))))
    table.add_row("Sitemaps", str(len(robots.get("sitemaps", []))))
    console.print(table)


def show_securitytxt(securitytxt):
    table = Table(title="security.txt")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Found", "YES" if securitytxt.get("found") else "NO")
    if securitytxt.get("found"):
        table.add_row("Location", str(securitytxt.get("location")))
        for key, values in securitytxt.get("fields", {}).items():
            table.add_row(key, ", ".join(values))
    console.print(table)


def show_whois(whois_data):
    if not whois_data or "error" in whois_data:
        return
    table = Table(title="WHOIS")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    for key, value in whois_data.items():
        if isinstance(value, list):
            value = ", ".join(value)
        table.add_row(key.replace("_", " ").title(), str(value))
    console.print(table)


def show_methods(methods):
    table = Table(title="HTTP Methods")
    table.add_column("Method", style="cyan")
    table.add_column("Status")
    table.add_column("Allowed")
    for method, data in methods.items():
        if method == "Allow Header":
            continue
        table.add_row(method, str(data["status"]), "YES" if data["allowed"] else "NO")
    console.print(table)
    if "Allow Header" in methods:
        console.print("\n[bold]Allow header:[/bold] " + ", ".join(methods["Allow Header"]))


def show_cors(cors):
    table = Table(title="CORS")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    for label, key in (
        ("Allow-Origin", "origin"),
        ("Allow-Credentials", "credentials"),
        ("Allow-Methods", "methods"),
        ("Allow-Headers", "headers"),
        ("Expose-Headers", "exposed_headers"),
        ("Max-Age", "max_age"),
    ):
        table.add_row(label, str(cors.get(key)))
    table.add_row("Origin reflected", "YES" if cors.get("reflected") else "NO")
    verdict = f"[red]YES - {cors.get('finding')}[/red]" if cors.get("vulnerable") else "NO"
    table.add_row("Potentially vulnerable", verdict)
    console.print(table)


def show_recommendations(recommendations):
    if not recommendations:
        console.print("\n[green]No recommendations - nice.[/green]")
        return
    table = Table(title="Security Recommendations")
    table.add_column("Severity")
    table.add_column("Issue")
    table.add_column("Recommendation")
    colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
    for rec in recommendations:
        color = colors.get(rec["severity"], "white")
        table.add_row(f"[{color}]{rec['severity']}[/{color}]", rec["title"], rec["recommendation"])
    console.print(table)


def main(argv=None):
    args = parse_arguments(argv)
    banner()

    target = normalize_url(args.url)
    console.print(f"\n[bold yellow]Scanning:[/bold yellow] {target}\n")

    results = scan(target, skip_ports=args.skip_ports, skip_subdomains=args.skip_subdomains)

    show_headers(results["headers"], results.get("errors", {}).get("headers"))
    show_cookies(results["cookies"])
    show_tls(results["tls"])
    show_dns(results["dns"])
    show_ports(results["ports"])
    show_subdomains(results["subdomains"])
    show_technologies(results["technologies"])
    show_robots(results["robots"])
    show_securitytxt(results["securitytxt"])
    show_whois(results["whois"])
    show_methods(results["methods"])
    show_cors(results["cors"])
    show_recommendations(results["recommendations"])

    if args.html or args.json or args.csv:
        os.makedirs(args.output, exist_ok=True)

    if args.html:
        path = generate_html_report(results, os.path.join(args.output, "report.html"))
        console.print(f"\n[green]HTML report:[/green] {path}")
    if args.json:
        path = generate_json_report(results, os.path.join(args.output, "report.json"))
        console.print(f"[green]JSON report:[/green] {path}")
    if args.csv:
        path = generate_csv_report(results, os.path.join(args.output, "report.csv"))
        console.print(f"[green]CSV report:[/green] {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
