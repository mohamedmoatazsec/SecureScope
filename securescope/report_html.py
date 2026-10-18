"""HTML report writer.

Every value that comes from the scanned target (header values, cookie
names, robots.txt rules, WHOIS fields, ...) is attacker-controlled, so it
is HTML-escaped before being written. A report viewer must never execute
content served by the site it describes.
"""

from datetime import datetime, timezone
from html import escape

from securescope import __version__

_STYLE = """
body { font-family: Arial, Helvetica, sans-serif; margin: 40px; background: #f5f5f5; color: #1a1a1a; }
h1 { color: #1565c0; }
h2 { margin-top: 32px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 25px; background: #fff; }
th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #1565c0; color: #fff; }
.meta { color: #555; }
"""


def _cell(value):
    """Render any scan value as escaped text."""
    if isinstance(value, dict):
        parts = [f"{escape(str(k))}: {escape(str(v))}" for k, v in value.items()]
        return "<br>".join(parts) if parts else "-"
    if isinstance(value, (list, tuple, set)):
        parts = [escape(str(v)) for v in value]
        return ", ".join(parts) if parts else "-"
    if value is None:
        return "-"
    return escape(str(value))


def render_html(data, generated=None):
    """Build the report document for `data` and return it as a string."""
    generated = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>SecureScope Report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        "<h1>SecureScope Report</h1>",
        f'<p class="meta">Generated {escape(generated)} by SecureScope {escape(__version__)}</p>',
    ]

    for section, values in data.items():
        parts.append(f"<h2>{escape(str(section))}</h2>")
        parts.append("<table>")

        if isinstance(values, dict):
            parts.append("<tr><th>Property</th><th>Value</th></tr>")
            for key, value in values.items():
                parts.append(f"<tr><td>{escape(str(key))}</td><td>{_cell(value)}</td></tr>")
        elif isinstance(values, list):
            parts.append("<tr><th>Item</th></tr>")
            if not values:
                parts.append("<tr><td>-</td></tr>")
            for item in values:
                parts.append(f"<tr><td>{_cell(item)}</td></tr>")
        else:
            parts.append(f"<tr><td>{_cell(values)}</td></tr>")

        parts.append("</table>")

    parts.extend(["</body>", "</html>", ""])
    return "\n".join(parts)


def generate_html_report(data, output_file="report.html"):
    """Write the HTML report for `data` to `output_file` and return the path."""
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(render_html(data))
    return output_file
