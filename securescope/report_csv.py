import csv
from datetime import datetime


def generate_csv_report(data, output_file="report.csv"):

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow(["SecureScope Report"])
        writer.writerow(["Generated", datetime.utcnow().isoformat() + "Z"])
        writer.writerow([])

        for section, values in data.items():

            writer.writerow([section])
            writer.writerow(["Property", "Value"])

            if isinstance(values, dict):

                for key, value in values.items():

                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)

                    writer.writerow([key, value])

            elif isinstance(values, list):

                for item in values:
                    writer.writerow(["Item", item])

            else:

                writer.writerow(["Value", values])

            writer.writerow([])

    return output_file