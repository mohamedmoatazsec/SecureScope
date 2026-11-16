"""CSV report writer."""

import csv
from datetime import datetime, timezone

from securescope import __version__


def _flatten(value):
    if isinstance(value, dict):
        return "; ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return "" if value is None else str(value)


def generate_csv_report(data, output_file="report.csv"):
    """Write the CSV report for `data` to `output_file` and return the path."""
    with open(output_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["SecureScope Report", __version__])
        writer.writerow(["Generated", datetime.now(timezone.utc).isoformat()])
        writer.writerow([])

        for section, values in data.items():
            writer.writerow([section])
            writer.writerow(["Property", "Value"])

            if isinstance(values, dict):
                for key, value in values.items():
                    writer.writerow([key, _flatten(value)])
            elif isinstance(values, list):
                for item in values:
                    writer.writerow(["Item", _flatten(item)])
            else:
                writer.writerow(["Value", _flatten(values)])

            writer.writerow([])

    return output_file
