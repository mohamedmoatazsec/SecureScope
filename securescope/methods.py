import requests


METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
]


def scan_methods(url):

    result = {}

    headers = {
        "User-Agent": "SecureScope/1.0"
    }

    for method in METHODS:

        try:

            response = requests.request(
                method,
                url,
                timeout=5,
                headers=headers,
                allow_redirects=False,
            )

            result[method] = {
                "status": response.status_code,
                "allowed": response.status_code not in (
                    405,
                    501,
                ),
            }

        except Exception:

            result[method] = {
                "status": None,
                "allowed": False,
            }

    try:

        options = requests.options(
            url,
            timeout=5,
            headers=headers,
        )

        allow = options.headers.get("Allow")

        if allow:

            result["Allow Header"] = [
                item.strip()
                for item in allow.split(",")
            ]

    except Exception:
        pass

    return result