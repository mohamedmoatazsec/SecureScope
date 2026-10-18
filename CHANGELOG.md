# Changelog

All notable changes to SecureScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.1] - 2026-10-18

A hardening release from reviewing the scanner's own attack surface: everything a hostile
target can send is now treated as data in every output, and the scanner cannot be steered or
exhausted by the site it is scanning.

### Security
- **Console output could be crashed or styled by the target.** Header values were passed to
  the console library's markup parser; a `Server: [/]` header raised an error and aborted the
  report, and `[link=…]` could inject styling. All target-derived text is now escaped.
- **CSV formula injection.** Cells beginning with `=`, `+`, `-`, `@`, tab or carriage return are
  prefixed with a quote so a header such as `Server: =HYPERLINK(...)` is literal text in Excel
  and LibreOffice.
- **Markdown output could carry raw HTML** from the target into job summaries and pull-request
  comments. Target-derived text is HTML-escaped and evidence is kept inside code spans that
  the target cannot break out of.
- **Redirects are followed by hand**, at most 5 hops, and a public target can no longer redirect
  the scanner into loopback, link-local or private address space (a scanner in CI would
  otherwise be a way to reach cloud metadata endpoints and internal services). A refused hop
  is reported as `REDIRECT-TO-INTERNAL-ADDRESS`.
- **Response bodies are capped** at 2 MB (header-only probes read nothing), and evidence values
  are capped at 1000 characters, so a target cannot exhaust memory or bloat reports.
- GitHub Action inputs are passed through environment variables instead of being interpolated
  into the shell script.
- CodeQL (security-extended) runs on every push and weekly; Dependabot keeps actions, Python
  dependencies and the base image updated.

### Added
- `target` check: redirect chain facts, `REDIRECT-HTTPS-TO-HTTP` (medium) when an HTTPS page
  redirects to plain HTTP, `TARGET-REDIRECTED` (info) when the final host differs, and
  `RESPONSE-BODY-TRUNCATED` (info).

### Fixed
- `CORS-NO-VARY-ORIGIN` fired for a fixed, non-reflected `Access-Control-Allow-Origin`; it now
  only applies when the origin is reflected.
- A malformed `--baseline` file produces a clear error instead of a traceback.

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
