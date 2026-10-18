"""JSON report: the canonical, machine-readable form every other format derives from."""

from __future__ import annotations

import json

from securescope.scanner import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
