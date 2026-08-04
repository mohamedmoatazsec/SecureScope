from securescope.headers import scan_headers
from securescope.tls import scan_tls
from securescope.robots import scan_robots
from securescope.securitytxt import scan_securitytxt
from securescope.technologies import detect_technologies
from securescope.dns import scan_dns
from securescope.methods import scan_methods
from securescope.cors import scan_cors
from securescope.recommendations import generate_recommendations
from securescope.portscan import scan_ports
from securescope.whois import scan_whois
from securescope.subdomains import scan_subdomains


def scan(url):

    headers, cookies = scan_headers(url)

    ports = scan_ports(url)


    results = {

        "headers": headers,

        "cookies": cookies,

        "tls": scan_tls(url),

        "robots": scan_robots(url),

        "securitytxt": scan_securitytxt(url),

        "technologies": detect_technologies(url),

        "dns": scan_dns(url),

        "methods": scan_methods(url),

        "cors": scan_cors(url),

        "whois": scan_whois(url),

        "ports": ports,

        "subdomains": scan_subdomains(url),
    }

    results["recommendations"] = generate_recommendations(results)

    return results