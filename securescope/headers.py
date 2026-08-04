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

        results = {}

        for header in SECURITY_HEADERS:
            results[header] = header in response.headers

        return results

    except requests.RequestException as e:
        print(f"Error: {e}")
        return None