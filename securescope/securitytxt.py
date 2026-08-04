import requests
from urllib.parse import urljoin


SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]


def scan_securitytxt(url):

    result = {
        "found": False,
        "location": None,
        "status": None,
        "fields": {},
    }

    headers = {
        "User-Agent": "SecureScope/1.0"
    }

    try:

        for path in SECURITY_TXT_PATHS:

            target = urljoin(url, path)

            response = requests.get(
                target,
                timeout=10,
                headers=headers,
            )

            if response.status_code != 200:
                continue

            result["found"] = True
            result["location"] = target
            result["status"] = response.status_code

            for line in response.text.splitlines():

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)

                key = key.strip()

                value = value.strip()

                if key not in result["fields"]:
                    result["fields"][key] = []

                result["fields"][key].append(value)

            return result

        return result

    except Exception as e:

        result["error"] = str(e)

        return result