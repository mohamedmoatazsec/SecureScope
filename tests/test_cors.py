from securescope.cors import PROBE_ORIGIN, analyze_cors


def test_no_cors_headers_is_not_vulnerable():
    result = analyze_cors({})
    assert result["origin"] is None
    assert result["vulnerable"] is False
    assert result["finding"] is None


def test_reflected_origin_with_credentials_is_vulnerable():
    result = analyze_cors(
        {
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }
    )
    assert result["reflected"] is True
    assert result["vulnerable"] is True
    assert "reflected" in result["finding"].lower()


def test_reflected_origin_without_credentials_is_flagged_but_not_vulnerable():
    result = analyze_cors({"Access-Control-Allow-Origin": PROBE_ORIGIN})
    assert result["reflected"] is True
    assert result["vulnerable"] is False
    assert result["finding"] is not None


def test_null_origin_with_credentials_is_vulnerable():
    result = analyze_cors({"access-control-allow-origin": "null", "access-control-allow-credentials": "TRUE"})
    assert result["vulnerable"] is True


def test_wildcard_with_credentials_is_flagged():
    result = analyze_cors({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert result["vulnerable"] is True
    assert "wildcard" in result["finding"].lower()


def test_fixed_allowlist_is_fine():
    result = analyze_cors(
        {
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST",
        }
    )
    assert result["reflected"] is False
    assert result["vulnerable"] is False
    assert result["methods"] == "GET, POST"
