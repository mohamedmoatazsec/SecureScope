import csv
import json

from securescope import __version__
from securescope.report_csv import generate_csv_report
from securescope.report_html import generate_html_report, render_html
from securescope.report_json import build_json_report, generate_json_report

SAMPLE = {
    "target": "https://example.test",
    "headers": {"Content-Security-Policy": True, "X-Frame-Options": False},
    "cookies": [{"name": "sid", "secure": True, "httponly": False, "samesite": None}],
    "technologies": {"headers": {"Server": "nginx"}, "technologies": [("Nginx", "HIGH")]},
    "recommendations": [],
}


def test_html_report_escapes_values_from_the_target():
    hostile = {
        "technologies": {"headers": {"Server": "<script>alert(1)</script>"}},
        "cookies": [{"name": '"><img src=x onerror=alert(1)>'}],
        "robots": {"disallow": ["</td><script>alert(2)</script>"]},
    }
    html = render_html(hostile, generated="2026-01-01 00:00:00 UTC")

    # No raw tag from the target survives; it is rendered as inert text.
    assert "<script" not in html
    assert "<img" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_report_contains_sections_and_version(tmp_path):
    path = generate_html_report(SAMPLE, tmp_path / "r.html")
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert str(path).endswith("r.html")
    assert "<h2>headers</h2>" in html
    assert "Content-Security-Policy" in html
    assert __version__ in html


def test_json_report_round_trips(tmp_path):
    doc = build_json_report(SAMPLE, generated="2026-01-01T00:00:00+00:00")
    assert doc["tool"] == "SecureScope"
    assert doc["version"] == __version__
    assert doc["results"]["target"] == "https://example.test"

    generate_json_report(SAMPLE, tmp_path / "r.json")
    loaded = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert loaded["results"]["headers"]["X-Frame-Options"] is False


def test_csv_report_flattens_nested_values(tmp_path):
    generate_csv_report(SAMPLE, tmp_path / "r.csv")
    rows = list(csv.reader((tmp_path / "r.csv").open(encoding="utf-8")))
    assert rows[0][0] == "SecureScope Report"
    flat = ["|".join(r) for r in rows]
    assert any(r.startswith("Content-Security-Policy|True") for r in flat)
    assert any("Server=nginx" in r for r in flat)
