from urllib.parse import urlparse
import whois
from datetime import datetime


def scan_whois(url):

    hostname = urlparse(url).hostname

    if hostname is None:
        hostname = url

    result = {}

    try:

        w = whois.whois(hostname)

        result["domain"] = hostname
        result["registrar"] = str(w.registrar)

        creation = w.creation_date
        expiration = w.expiration_date
        updated = w.updated_date

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(expiration, list):
            expiration = expiration[0]

        if isinstance(updated, list):
            updated = updated[0]

        result["creation_date"] = (
            creation.strftime("%Y-%m-%d")
            if isinstance(creation, datetime)
            else str(creation)
        )

        result["expiration_date"] = (
            expiration.strftime("%Y-%m-%d")
            if isinstance(expiration, datetime)
            else str(expiration)
        )

        result["updated_date"] = (
            updated.strftime("%Y-%m-%d")
            if isinstance(updated, datetime)
            else str(updated)
        )

        result["name_servers"] = (
            sorted(list(w.name_servers))
            if w.name_servers
            else []
        )

    except Exception as e:

        result["error"] = str(e)

    return result