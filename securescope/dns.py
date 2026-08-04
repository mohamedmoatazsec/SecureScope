import socket


def scan_dns(url):
    hostname = (
        url.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    result = {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
    }

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None
        )

        ipv4 = set()
        ipv6 = set()

        for address in addresses:

            ip = address[4][0]

            if ":" in ip:
                ipv6.add(ip)
            else:
                ipv4.add(ip)

        result["ipv4"] = sorted(list(ipv4))
        result["ipv6"] = sorted(list(ipv6))

    except Exception as e:
        result["error"] = str(e)

    return result