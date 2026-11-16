from securescope.methods import parse_allow_header
from securescope.robots import parse_robots
from securescope.securitytxt import parse_security_txt
from securescope.technologies import fingerprint
from securescope.tls import hostname_from_url

ROBOTS = """
# comment line
User-agent: *
Disallow: /admin/   # trailing comment
Disallow: /private
Allow: /public
Sitemap: https://example.test/sitemap.xml
Crawl-delay: 10
Host: example.test
"""


def test_parse_robots_groups_rules():
    result = parse_robots(ROBOTS)
    assert result["disallow"] == ["/admin/", "/private"]
    assert result["allow"] == ["/public"]
    assert result["sitemaps"] == ["https://example.test/sitemap.xml"]
    assert result["crawl_delay"] == "10"
    assert result["hosts"] == ["example.test"]


def test_parse_robots_handles_empty_input():
    assert parse_robots("")["disallow"] == []


SECURITY_TXT = """
# Our security policy
Contact: mailto:security@example.test
Contact: https://example.test/report
Expires: 2027-01-01T00:00:00.000Z
Policy: https://example.test/security-policy
"""


def test_parse_security_txt_collects_repeated_fields():
    fields = parse_security_txt(SECURITY_TXT)
    assert fields["Contact"] == ["mailto:security@example.test", "https://example.test/report"]
    assert fields["Expires"] == ["2027-01-01T00:00:00.000Z"]
    assert "Policy" in fields


def test_parse_allow_header():
    assert parse_allow_header("GET, POST,HEAD , options") == ["GET", "POST", "HEAD", "OPTIONS"]
    assert parse_allow_header(None) == []
    assert parse_allow_header("") == []


def test_hostname_from_url():
    assert hostname_from_url("https://example.test/path?q=1") == "example.test"
    assert hostname_from_url("example.test") == "example.test"
    assert hostname_from_url("http://sub.example.test:8080/") == "sub.example.test"


def test_fingerprint_from_headers_and_html():
    result = fingerprint(
        {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2", "CF-RAY": "abc"},
        "<html><script src='/js/jquery.min.js'></script><link href='wp-content/x.css'></html>",
    )
    techs = dict(result["technologies"])
    assert techs["Nginx"] == "HIGH"
    assert techs["PHP/8.2"] == "HIGH"
    assert techs["jQuery"] == "MEDIUM"
    assert techs["WordPress"] == "MEDIUM"
    assert result["headers"]["CF-RAY"] == "abc"


def test_fingerprint_deduplicates_and_handles_empty_input():
    result = fingerprint({}, "")
    assert result["technologies"] == []
    assert result["headers"] == {}
