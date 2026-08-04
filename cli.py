import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from securescope.headers import scan_headers
from securescope.tls import scan_tls

console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold cyan]SecureScope[/bold cyan]\n"
            "[green]AI-powered Web Security Assessment Toolkit[/green]",
            border_style="blue",
        )
    )


def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] py cli.py <url>")
        return

    url = sys.argv[1]

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    banner()

    console.print(f"\n[bold yellow]Scanning:[/bold yellow] {url}\n")

    results, cookies = scan_headers(url)

    if results is None:
        return

    # ---------------- Headers ----------------

    table = Table(title="HTTP Security Headers")

    table.add_column("Header", style="cyan")
    table.add_column("Status", justify="center")

    score = 0

    for header, exists in results.items():
        if exists:
            table.add_row(header, "[green]PASS[/green]")
            score += 1
        else:
            table.add_row(header, "[red]FAIL[/red]")

    console.print(table)

    # ---------------- Cookies ----------------

    if cookies:
        cookie_table = Table(title="Cookies")

        cookie_table.add_column("Cookie", style="cyan")
        cookie_table.add_column("Secure", justify="center")
        cookie_table.add_column("HttpOnly", justify="center")

        for cookie in cookies:
            cookie_table.add_row(
                cookie["name"],
                "[green]PASS[/green]" if cookie["secure"] else "[red]FAIL[/red]",
                "[green]PASS[/green]" if cookie["httponly"] else "[red]FAIL[/red]",
            )

        console.print(cookie_table)

    # ---------------- TLS ----------------

    tls = scan_tls(url)

    if "error" not in tls:

        tls_table = Table(title="TLS Certificate")

        tls_table.add_column("Property", style="cyan")
        tls_table.add_column("Value")

        tls_table.add_row("Protocol", tls["protocol"])
        tls_table.add_row("Issuer", tls["issuer"])
        tls_table.add_row("Subject", tls["subject"])
        tls_table.add_row("Expires", tls["expires"])
        tls_table.add_row("Days Remaining", str(tls["days"]))

        console.print(tls_table)

    # ---------------- Score ----------------

    percent = int(score / len(results) * 100)

    if percent >= 80:
        color = "green"
    elif percent >= 60:
        color = "yellow"
    else:
        color = "red"

    console.print(f"\nSecurity Score: [{color}]{percent}%[/{color}]")


if __name__ == "__main__":
    main()