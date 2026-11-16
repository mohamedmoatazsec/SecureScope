# Changelog

All notable changes to SecureScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - 2026-10-18

### Security
- HTML reports now escape every value that came from the scanned target. Previously a
  malicious `Server` header, cookie name or `robots.txt` line could inject markup and script
  into the report (a stored HTML injection against whoever opened it).

### Fixed
- CORS analysis now detects the case that matters: an arbitrary `Origin` reflected in
  `Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true`. It also
  flags `null` origins with credentials. Wildcard-with-credentials is still reported.
- `HttpOnly` detection no longer relies on the string form of the cookie; `SameSite` is read too.
- An unreachable target no longer crashes the header table and recommendation engine
  (`scan_headers` returned `None`).
- A `403` answer to a probed HTTP method is reported as "not allowed" rather than "allowed".
- Certificate expiry maths uses timezone-aware datetimes.

### Added
- Installable package with a `securescope` console script (`pip install .`).
- `--output DIR`, `--skip-ports`, `--skip-subdomains` and `--version` options; bare hostnames
  default to `https://`.
- A real test suite (pytest) covering header evaluation, cookie attributes, CORS analysis,
  robots.txt / security.txt parsing, fingerprinting, recommendations and the three report
  writers. No network access needed.
- CI runs `ruff` and the tests on Python 3.9 to 3.13 instead of scanning a third-party site
  on every push.
- `SECURITY.md`, `CHANGELOG.md`, and a single `User-Agent` identifying the tool and version.

### Changed
- README rewritten: accurate description of what is checked, option reference, sample JSON
  output and a responsible-use note. The "AI-powered" tagline was removed because no such
  feature exists yet.
- Recommendations are sorted by severity and give concrete remediation text.

## [1.0.0] - 2026-08

Initial release: security headers, cookies, TLS, DNS, port scan, subdomains, technology
detection, robots.txt, security.txt, WHOIS, HTTP methods, CORS, recommendations, HTML/JSON/CSV
reports.
