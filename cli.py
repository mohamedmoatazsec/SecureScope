import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from securescope.scanner import scan

from securescope.report_html import generate_html_report
from securescope.report_json import generate_json_report
from securescope.report_csv import generate_csv_report

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]SecureScope[/bold cyan]\n"
            "[green]AI-powered Web Security Assessment Toolkit[/green]",
            border_style="cyan",
        )
    )


def parse_arguments():

    parser = argparse.ArgumentParser(
        description="SecureScope Web Security Toolkit"
    )

    parser.add_argument(
        "url",
        help="Target URL",
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON report",
    )

    parser.add_argument(
        "--csv",
        action="store_true",
        help="Generate CSV report",
    )

    return parser.parse_args()


def show_headers(headers):

    table = Table(title="HTTP Security Headers")

    table.add_column("Header", style="cyan")
    table.add_column("Status", justify="center")

    score = 0

    for header, exists in headers.items():

        if exists:

            table.add_row(
                header,
                "[green]PASS[/green]"
            )

            score += 1

        else:

            table.add_row(
                header,
                "[red]FAIL[/red]"
            )

    console.print(table)

    percent = int(score / len(headers) * 100)

    if percent >= 80:
        color = "green"
    elif percent >= 60:
        color = "yellow"
    else:
        color = "red"

    console.print(
        f"\nSecurity Score: [{color}]{percent}%[/{color}]"
    )


def show_cookies(cookies):

    if not cookies:
        return

    table = Table(title="Cookies")

    table.add_column("Cookie", style="cyan")
    table.add_column("Secure", justify="center")
    table.add_column("HttpOnly", justify="center")

    for cookie in cookies:

        table.add_row(
            cookie["name"],
            "[green]PASS[/green]" if cookie["secure"] else "[red]FAIL[/red]",
            "[green]PASS[/green]" if cookie["httponly"] else "[red]FAIL[/red]",
        )

    console.print(table)


def show_tls(tls):

    if "error" in tls:
        return

    table = Table(title="TLS Certificate")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Protocol", tls["protocol"])
    table.add_row("Issuer", tls["issuer"])
    table.add_row("Subject", tls["subject"])
    table.add_row("Expires", tls["expires"])
    table.add_row("Days Remaining", str(tls["days"]))

    console.print(table)

def show_dns(dns):

    table = Table(title="DNS Information")

    table.add_column("Type", style="cyan")
    table.add_column("Value")

    for ip in dns.get("ipv4", []):
        table.add_row("IPv4", ip)

    for ip in dns.get("ipv6", []):
        table.add_row("IPv6", ip)

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

        table.add_row(
        port["ip"],
        str(port["port"]),
        port["service"],
        port["status"],
        )

    console.print(table)


def show_subdomains(subdomains):

    if not subdomains:
        return

    table = Table(title="Subdomains")

    table.add_column("Subdomain")
    table.add_column("IP")
    table.add_column("HTTP")

    for sub in subdomains:

        table.add_row(
        sub["subdomain"],
        sub["ip"],
        str(sub["status"]) if sub["status"] else "-",
        )

    console.print(table)


def show_technologies(technologies):

    table = Table(title="Detected Technologies")

    table.add_column("Technology")
    table.add_column("Confidence")

    techs = technologies.get("technologies", [])

    if techs:

       for tech, confidence in techs:
           table.add_row(tech, confidence)
    else:

        table.add_row("No technologies detected")

    console.print(table)


def show_robots(robots):

    table = Table(title="robots.txt")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row(
        "Found",
        "YES" if robots.get("found") else "NO"
    )

    table.add_row(
        "HTTP Status",
        str(robots.get("status"))
    )

    table.add_row(
        "Disallow Rules",
        str(len(robots.get("disallow", [])))
    )

    table.add_row(
        "Allow Rules",
        str(len(robots.get("allow", [])))
    )

    table.add_row(
        "Sitemaps",
        str(len(robots.get("sitemaps", [])))
    )

    console.print(table)


def show_securitytxt(securitytxt):

    table = Table(title="security.txt")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row(
        "Found",
        "YES" if securitytxt.get("found") else "NO"
    )

    if securitytxt.get("found"):

        table.add_row(
            "Location",
            securitytxt.get("location")
        )

        for key, value in securitytxt.get("fields", {}).items():

            table.add_row(
                key,
                ", ".join(value)
            )

    console.print(table)


def show_whois(whois_data):

    if "error" in whois_data:
        return

    table = Table(title="WHOIS")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    for key, value in whois_data.items():

        if isinstance(value, list):
            value = ", ".join(value)

        table.add_row(
            key.replace("_", " ").title(),
            str(value),
        )

    console.print(table)

def show_methods(methods):

    table = Table(title="HTTP Methods")

    table.add_column("Method", style="cyan")
    table.add_column("Status")
    table.add_column("Allowed")

    for method, data in methods.items():

        if method == "Allow Header":
            continue

        table.add_row(
            method,
            str(data["status"]),
            "YES" if data["allowed"] else "NO",
        )

    console.print(table)

    if "Allow Header" in methods:

        console.print(
            "\n[bold]Allow Header:[/bold] "
            + ", ".join(methods["Allow Header"])
        )


def show_cors(cors):

    table = Table(title="CORS")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row(
        "Allow Origin",
        str(cors.get("origin"))
    )

    table.add_row(
        "Credentials",
        str(cors.get("credentials"))
    )

    table.add_row(
        "Methods",
        str(cors.get("methods"))
    )

    table.add_row(
        "Headers",
        str(cors.get("headers"))
    )

    table.add_row(
        "Exposed Headers",
        str(cors.get("exposed_headers"))
    )

    table.add_row(
        "Max Age",
        str(cors.get("max_age"))
    )

    table.add_row(
        "Potentially Vulnerable",
        "YES" if cors.get("vulnerable") else "NO"
    )

    console.print(table)


def show_recommendations(recommendations):

    if not recommendations:
        return

    table = Table(title="Security Recommendations")

    table.add_column("Severity", style="red")
    table.add_column("Issue")
    table.add_column("Recommendation")

    for rec in recommendations:

        table.add_row(
            rec["severity"],
            rec["title"],
            rec["recommendation"],
        )

    console.print(table)


def main():

    args = parse_arguments()

    banner()

    console.print(
        f"\n[bold yellow]Scanning:[/bold yellow] {args.url}\n"
    )

    results = scan(args.url)

    show_headers(results["headers"])
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

    if args.html:

        filename = generate_html_report(results)

        console.print(
            f"\n[green]HTML report generated:[/green] {filename}"
        )

    if args.json:

        filename = generate_json_report(results)

        console.print(
            f"\n[green]JSON report generated:[/green] {filename}"
        )

    if args.csv:

        filename = generate_csv_report(results)

        console.print(
            f"\n[green]CSV report generated:[/green] {filename}"
        )


if __name__ == "__main__":
    main()