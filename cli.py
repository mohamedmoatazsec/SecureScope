import sys
from securescope.headers import scan_headers


def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <url>")
        return

    url = sys.argv[1]

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("=" * 50)
    print("SecureScope v1.0")
    print("=" * 50)

    print(f"\nScanning: {url}\n")

    results = scan_headers(url)

    if results is None:
        return

    score = 0

    for header, exists in results.items():
        if exists:
            print(f"[+] {header}")
            score += 1
        else:
            print(f"[-] {header}")

    percent = int((score / len(results)) * 100)

    print(f"\nSecurity Score: {percent}%")
    print("=" * 50)


if __name__ == "__main__":
    main()