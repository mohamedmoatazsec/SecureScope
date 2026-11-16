"""Report writers. `render(report, fmt)` returns the document text for a format."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from securescope.reports.csv_report import render_csv
from securescope.reports.html_report import render_html
from securescope.reports.json_report import render_json
from securescope.reports.markdown_report import render_markdown
from securescope.reports.sarif_report import render_sarif
from securescope.scanner import Report

RENDERERS: dict[str, Callable[[Report], str]] = {
    "json": render_json,
    "html": render_html,
    "md": render_markdown,
    "sarif": render_sarif,
    "csv": render_csv,
}

EXTENSIONS = {"json": "json", "html": "html", "md": "md", "sarif": "sarif", "csv": "csv"}

FORMATS = list(RENDERERS)


def render(report: Report, fmt: str) -> str:
    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:
        raise ValueError(f"unknown report format {fmt!r} (choose from {', '.join(FORMATS)})") from exc
    return renderer(report)


def write(report: Report, fmt: str, directory: str, name: str = "securescope-report") -> Path:
    path = Path(directory) / f"{name}.{EXTENSIONS[fmt]}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report, fmt), encoding="utf-8")
    return path


__all__ = ["FORMATS", "render", "write"]
