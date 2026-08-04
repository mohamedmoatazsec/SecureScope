from datetime import datetime


def generate_html_report(data, output_file="report.html"):

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>SecureScope Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin:40px;
    background:#f5f5f5;
}}

h1 {{
    color:#1565c0;
}}

table {{
    border-collapse:collapse;
    width:100%;
    margin-bottom:25px;
    background:white;
}}

th,td {{
    border:1px solid #ddd;
    padding:10px;
}}

th {{
    background:#1565c0;
    color:white;
}}

.pass {{
    color:green;
    font-weight:bold;
}}

.fail {{
    color:red;
    font-weight:bold;
}}

.section {{
    margin-top:40px;
}}

</style>

</head>

<body>

<h1>SecureScope Report</h1>

<p>
Generated:
{datetime.now()}
</p>

"""

    for section, values in data.items():

        html += f'<div class="section">'
        html += f"<h2>{section}</h2>"

        html += "<table>"

        html += """
<tr>
<th>Property</th>
<th>Value</th>
</tr>
"""

        if isinstance(values, dict):

            for key, value in values.items():

                html += f"""
<tr>
<td>{key}</td>
<td>{value}</td>
</tr>
"""

        elif isinstance(values, list):

            for item in values:

                html += f"""
<tr>
<td colspan="2">{item}</td>
</tr>
"""

        else:

            html += f"""
<tr>
<td colspan="2">{values}</td>
</tr>
"""

        html += "</table>"
        html += "</div>"

    html += """

</body>

</html>

"""

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(html)

    return output_file