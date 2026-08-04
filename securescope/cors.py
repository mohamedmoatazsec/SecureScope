import requests


def scan_cors(url):

    result = {
        "origin": None,
        "credentials": None,
        "methods": None,
        "headers": None,
        "exposed_headers": None,
        "max_age": None,
        "vulnerable": False,
    }

    headers = {
        "Origin": "https://securescope.local",
        "User-Agent": "SecureScope/1.0",
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=10,
        )

        h = response.headers

        result["origin"] = h.get(
            "Access-Control-Allow-Origin"
        )

        result["credentials"] = h.get(
            "Access-Control-Allow-Credentials"
        )

        result["methods"] = h.get(
            "Access-Control-Allow-Methods"
        )

        result["headers"] = h.get(
            "Access-Control-Allow-Headers"
        )

        result["exposed_headers"] = h.get(
            "Access-Control-Expose-Headers"
        )

        result["max_age"] = h.get(
            "Access-Control-Max-Age"
        )

        if (
            result["origin"] == "*"
            and result["credentials"] == "true"
        ):
            result["vulnerable"] = True

    except Exception as e:

        result["error"] = str(e)

    return result