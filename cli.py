import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from securescope.headers import scan_headers

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

    results = scan_headers(url)

    if results is None:
        return

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