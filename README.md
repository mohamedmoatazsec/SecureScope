# SecureScope

AI-powered Web Security Assessment Toolkit.

## Features

- HTTP Security Headers Scanner
- Security Score Calculation
- Fast CLI Interface
- HTTPS Support

## Installation

```bash
git clone https://github.com/mohamedmoatazsec/SecureScope.git
cd SecureScope
py -m pip install -r requirements.txt
```

## Usage

```bash
py cli.py https://github.com
```

Example Output

```
==================================================
SecureScope v1.0
==================================================

Scanning: https://github.com

[+] Content-Security-Policy
[+] Strict-Transport-Security
[+] X-Frame-Options
[+] X-Content-Type-Options
[+] Referrer-Policy
[-] Permissions-Policy

Security Score: 83%
```

## Roadmap

- Cookie Scanner
- TLS Scanner
- robots.txt Analyzer
- HTML Report
- JSON Report
- GitHub Actions

## License

MIT
