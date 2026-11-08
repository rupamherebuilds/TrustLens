from modules.url import analyze_url


def test_ip_based_url():
    findings = analyze_url("http://192.168.1.1/login")

    finding_ids = [finding.id for finding in findings]

    assert "IP_BASED_URL" in finding_ids


def test_at_symbol_url():
    findings = analyze_url("http://google.com@evil.com")

    finding_ids = [finding.id for finding in findings]

    assert "URL_AT_SYMBOL" in finding_ids


def test_punycode_url():
    findings = analyze_url("https://xn--pple-43d.com")

    finding_ids = [finding.id for finding in findings]

    assert "PUNYCODE_DOMAIN" in finding_ids


def test_long_url():
    url = "https://example.com/" + "a" * 150

    findings = analyze_url(url)

    finding_ids = [finding.id for finding in findings]

    assert "LONG_URL" in finding_ids


def test_many_subdomains():
    url = "https://a.b.c.d.e.example.com"

    findings = analyze_url(url)

    finding_ids = [finding.id for finding in findings]

    assert "EXCESSIVE_SUBDOMAINS" in finding_ids


def test_brand_impersonation():
    findings = analyze_url("https://paypal.com.evil.org")

    finding_ids = [finding.id for finding in findings]

    assert "BRAND_IMPERSONATION" in finding_ids