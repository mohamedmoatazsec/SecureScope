"""JSON report writer."""

import json
from datetime import datetime, timezone

from securescope import __version__


def build_json_report(data, generated=None):
    """Return the report document as a dict (serialisable with json)."""
    return {
        "tool": "SecureScope",
        "version": __version__,
        "generated": generated or datetime.now(timezone.utc).isoformat(),
        "results": data,
    }


def generate_json_report(data, output_file="report.json"):
    """Write the JSON report for `data` to `output_file` and return the path."""
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(build_json_report(data), handle, indent=4, ensure_ascii=False, default=str)
    return output_file
