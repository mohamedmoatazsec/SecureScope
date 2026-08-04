import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def scan_headers(url):
    try:
        response = requests.get(url, timeout=10)

        headers_result = {}

        for header in SECURITY_HEADERS:
            headers_result[header] = header in response.headers

        cookies = []

        for cookie in response.cookies:
            cookies.append(
                {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": "HttpOnly" in str(cookie),
                }
            )

        return headers_result, cookies

    except requests.RequestException as e:
        print(f"Error: {e}")
        return None, []