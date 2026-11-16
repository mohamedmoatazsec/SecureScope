"""security.txt (RFC 9116) locations and parsing."""

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]


def parse_security_txt(text):
    """Parse security.txt fields into {field: [values]}. Pure function."""
    fields = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip(), []).append(value.strip())
    return fields
