# Changelog

All notable changes to SecureScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - 2026-10-18

A rewrite around one idea: every result is an evidence-backed finding with a stable id, a
severity, a confidence level and a fix, and everything else (console, HTML, JSON, SARIF,
Markdown, CSV, grades, baselines, exit codes) derives from that.

### Added
- **Finding model and grades.** Findings carry `id`, `severity`, `confidence`, `evidence`,
  `remediation`, `references` and `cwe`; each target gets a 0-100 score and an A+ to F grade.
- **Content-Security-Policy evaluator.** Missing / report-only policies, no script restriction,
  `'unsafe-inline'` without nonces or hashes, `'unsafe-eval'`, wildcard and scheme-only script
  sources, wildcard hosts, missing `object-src` / `base-uri` / `form-action`, duplicate and
  unknown directives, no reporting endpoint; `'strict-dynamic'` is understood.
- **Header quality checks** instead of presence checks: HSTS `max-age` and `includeSubDomains`,
  `X-Frame-Options` values (`ALLOW-FROM` is flagged), `frame-ancestors` wildcards,
  `Referrer-Policy` values, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, legacy
  `X-XSS-Protection: 1`, `Cache-Control: public` on HTML.
- **Cookie checks** read from the raw `Set-Cookie` headers: `SameSite=None` without `Secure`,
  `__Host-` / `__Secure-` prefix rules, domain scope; session-like cookies are rated higher;
  cookie values are redacted in evidence.
- **TLS checks**: certificate validation errors, expiry windows, negotiated protocol and cipher,
  whether TLS 1.0/1.1 are accepted and TLS 1.3 offered, and the `http://` to `https://` redirect.
- **Information disclosure**: versions in `Server` and stack-announcing headers.
- **Reports**: SARIF 2.1.0 (GitHub code scanning), Markdown (PR comments / job summaries), a
  redesigned self-contained HTML report with severity filters, JSON with a published schema, CSV.
- **CI gate**: `--fail-on SEV` (exit code 2), `--baseline FILE` so only new findings fail a run,
  `--stdout FMT` for piping, `-q` for one-line summaries.
- **Ergonomics for engagements**: `--proxy` (e.g. Burp), `-H` / `--cookie` / `--user-agent` for
  authenticated scans, `--insecure`, `--timeout`, `--retries`, multiple targets with
  `-t targets.txt` scanned in parallel, `--checks` / `--skip-checks`, `--list-checks`.
- A GitHub Action (`uses: mohamedmoatazsec/SecureScope@v2`), a Dockerfile and a release workflow
  that publishes the image to GHCR.
- 75 offline tests, including end-to-end scans against a local HTTP and HTTPS test server.

### Changed
- Port probing, subdomain resolution and WHOIS are now opt-in (`--ports`, `--subdomains`,
  `--whois`); `--skip-ports` / `--skip-subdomains` are gone. The default scan is HTTP and TLS
  only, which is faster and quieter.
- The HTTP-methods check sends only `OPTIONS` and `TRACE`. It no longer fires `PUT`, `DELETE` or
  `PATCH` at the target; methods advertised in `Allow` are reported for manual verification.
- Report files are named `securescope-report.<ext>` (override with `-n`) and formats are chosen
  with `-f`; `--html` / `--json` / `--csv` flags are replaced.
- `python-whois` is an optional extra: `pip install "securescope[whois]"`.
- Python API: `securescope.scanner.scan_target(url, ScanConfig)` returns a `ScanResult`;
  `scan_targets([...])` returns a `Report`. The 1.x `scan()` dict is gone.

### Fixed
- `--insecure` and `--proxy` could be silently overridden by `REQUESTS_CA_BUNDLE` / `HTTPS_PROXY`
  environment variables; both are now passed per request.
- Cookies whose `Expires` attribute contains a comma are no longer split in two.

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
