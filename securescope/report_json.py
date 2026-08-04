import json
from datetime import datetime


def generate_json_report(data, output_file="report.json"):
    report = {
        "tool": "SecureScope",
        "version": "1.0",
        "generated": datetime.utcnow().isoformat() + "Z",
        "results": data,
    }

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False,
        )

    return output_file