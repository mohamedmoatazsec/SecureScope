"""CORS configuration checks.

The scan sends a request with an attacker-controlled Origin and inspects
the Access-Control-* response headers. A deployment is flagged as
potentially vulnerable when it would let a foreign origin read
credentialed responses, which is the combination that actually matters
to an attacker:

* the sent origin is reflected back in Access-Control-Allow-Origin and
  Access-Control-Allow-Credentials is true;
* Access-Control-Allow-Origin is "null" with credentials enabled
  (sandboxed iframes and some redirects produce a null origin);
* Access-Control-Allow-Origin is "*" with credentials enabled. Browsers
  reject this combination, but it still signals a misconfigured policy.
"""

import requests

from securescope import USER_AGENT

PROBE_ORIGIN = "https://securescope-probe.invalid"


def analyze_cors(response_headers, sent_origin=PROBE_ORIGIN):
    """Evaluate CORS headers from a response. Pure function, no network."""
    lowered = {str(k).lower(): v for k, v in response_headers.items()}

    def get(name):
        return lowered.get(name.lower())

    origin = get("Access-Control-Allow-Origin")
    credentials = get("Access-Control-Allow-Credentials")
    credentials_on = str(credentials).strip().lower() == "true"

    reflected = origin is not None and origin.strip() == sent_origin
    null_origin = origin is not None and origin.strip().lower() == "null"
    wildcard = origin is not None and origin.strip() == "*"

    if reflected and credentials_on:
        finding = "Arbitrary origin reflected with credentials"
    elif null_origin and credentials_on:
        finding = "null origin allowed with credentials"
    elif wildcard and credentials_on:
        finding = "Wildcard origin combined with credentials"
    elif reflected:
        finding = "Arbitrary origin reflected (no credentials)"
    else:
        finding = None

    return {
        "origin": origin,
        "credentials": credentials,
        "methods": get("Access-Control-Allow-Methods"),
        "headers": get("Access-Control-Allow-Headers"),
        "exposed_headers": get("Access-Control-Expose-Headers"),
        "max_age": get("Access-Control-Max-Age"),
        "reflected": reflected,
        "vulnerable": finding is not None and credentials_on,
        "finding": finding,
    }


def scan_cors(url, timeout=10):
    """Send a cross-origin probe request to `url` and analyse the answer."""
    try:
        response = requests.get(
            url,
            headers={"Origin": PROBE_ORIGIN, "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        result = analyze_cors({})
        result["error"] = str(exc)
        return result

    return analyze_cors(response.headers, PROBE_ORIGIN)
