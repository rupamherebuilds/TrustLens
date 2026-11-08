from modules.headers import assert_public
from modules.headers import findings_from_headers


def test_assert_public_rejects_localhost():
    assert assert_public("localhost") is False


def test_assert_public_rejects_private_ip():
    assert assert_public("192.168.1.1") is False


def test_assert_public_accepts_public_ip():
    assert assert_public("8.8.8.8") is True

def test_missing_security_headers():
    headers = {}

    findings = findings_from_headers(
        headers,
        "https://example.com"
    )

    finding_ids = [finding.id for finding in findings]

    assert "MISSING_HSTS" in finding_ids
    assert "MISSING_CSP" in finding_ids
    assert "MISSING_FRAME_PROTECTION" in finding_ids

def test_insecure_http_detection():
    headers = {}

    findings = findings_from_headers(
        headers,
        "http://example.com"
    )

    finding_ids = [finding.id for finding in findings]

    assert "INSECURE_HTTP" in finding_ids


def test_security_headers_present():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        "x-frame-options": "DENY"
    }

    findings = findings_from_headers(
        headers,
        "https://example.com"
    )

    finding_ids = [finding.id for finding in findings]

    assert "MISSING_HSTS" not in finding_ids
    assert "MISSING_CSP" not in finding_ids
    assert "MISSING_FRAME_PROTECTION" not in finding_ids