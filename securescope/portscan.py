import socket
from urllib.parse import urlparse


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


def scan_ports(url):

    hostname = urlparse(url).hostname

    if not hostname:
        hostname = url

    results = []

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        checked = set()

        for addr in addresses:

            ip = addr[4][0]

            if ip in checked:
                continue

            checked.add(ip)

            family = addr[0]

            for port, service in COMMON_PORTS.items():

                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(0.5)

                try:

                    if sock.connect_ex((ip, port)) == 0:

                        results.append({
                            "ip": ip,
                            "port": port,
                            "service": service,
                            "status": "OPEN",
                        })

                except Exception:
                    pass

                finally:
                    sock.close()

    except Exception:
        pass

    return results