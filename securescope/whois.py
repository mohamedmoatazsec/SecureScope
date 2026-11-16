"""WHOIS lookup for the target's registrable domain."""

from datetime import datetime

from securescope.config import hostname_from_url


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _date(value):
    value = _first(value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value) if value is not None else None


def scan_whois(url):
    """Return registrar, key dates and name servers for the target domain."""
    hostname = hostname_from_url(url)
    result = {"domain": hostname}

    try:
        import whois  # python-whois; imported lazily so the rest works without it
    except ImportError:
        result["error"] = "python-whois is not installed (pip install 'securescope[whois]')"
        return result

    try:
        record = whois.whois(hostname)
    except Exception as exc:  # the library raises many unrelated exception types
        result["error"] = str(exc)
        return result

    result["registrar"] = str(record.registrar) if record.registrar else None
    result["creation_date"] = _date(record.creation_date)
    result["expiration_date"] = _date(record.expiration_date)
    result["updated_date"] = _date(record.updated_date)
    result["name_servers"] = sorted(str(ns).lower() for ns in (record.name_servers or []))
    return result
