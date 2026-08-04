import requests


def detect_technologies(url):

    result = {
        "headers": {},
        "technologies": [],
    }

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "SecureScope/1.0"},
        )

        headers = response.headers
        html = response.text.lower()

        # حفظ أهم الـ Headers
        interesting = [
            "Server",
            "X-Powered-By",
            "CF-RAY",
            "CF-Cache-Status",
        ]

        for h in interesting:
            if h in headers:
                result["headers"][h] = headers[h]

        # -------- HIGH confidence --------

        if headers.get("Server", "").lower() == "github.com":
            result["technologies"].append(
                ("GitHub", "HIGH")
            )

        if "cloudflare" in headers.get("Server", "").lower():
            result["technologies"].append(
                ("Cloudflare", "HIGH")
            )

        if "nginx" in headers.get("Server", "").lower():
            result["technologies"].append(
                ("Nginx", "HIGH")
            )

        if "apache" in headers.get("Server", "").lower():
            result["technologies"].append(
                ("Apache", "HIGH")
            )

        if "microsoft-iis" in headers.get("Server", "").lower():
            result["technologies"].append(
                ("Microsoft IIS", "HIGH")
            )

        # -------- MEDIUM confidence --------

        if "bootstrap" in html:
            result["technologies"].append(
                ("Bootstrap", "MEDIUM")
            )

        if "jquery" in html:
            result["technologies"].append(
                ("jQuery", "MEDIUM")
            )

        # إزالة التكرار
        result["technologies"] = list(
            dict.fromkeys(result["technologies"])
        )

        return result

    except Exception as e:

        result["error"] = str(e)

        return result