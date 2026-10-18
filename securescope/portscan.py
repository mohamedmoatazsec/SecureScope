"""TCP connect scan of a short list of common ports.

Only use this against hosts you are authorised to test. The scan is a
plain connect() per port with a short timeout; it is deliberately small
and sequential rather than a full port sweep.
"""

import socket

from securescope.tls import hostname_from_url

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def scan_ports(url, ports=None, timeout=0.5):
    """Return a list of {ip, port, service, status} for ports that accept a connection."""
    hostname = hostname_from_url(url)
    ports = ports or COMMON_PORTS
    results = []

    try:
        addresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return results

    checked = set()
    for family, _, _, _, sockaddr in addresses:
        ip = sockaddr[0]
        if ip in checked:
            continue
        checked.add(ip)

        for port, service in ports.items():
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    results.append({"ip": ip, "port": port, "service": service, "status": "OPEN"})
            except OSError:
                pass
            finally:
                sock.close()

    return results
