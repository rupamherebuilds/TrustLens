from core.models import Finding
from core.correlate import correlate


def test_brand_and_ip_correlation():
    findings = [
        Finding(
            id="BRAND_IMPERSONATION",
            source="url",
            description="Brand impersonation detected.",
            points=25
        ),
        Finding(
            id="IP_BASED_URL",
            source="url",
            description="IP based URL detected.",
            points=20
        )
    ]

    result = correlate(findings)

    assert len(result) == 1
    assert result[0].id == "BRAND_AND_IP_URL"


def test_no_correlation_for_safe_input():
    findings = [
        Finding(
            id="LONG_URL",
            source="url",
            description="Long URL detected.",
            points=10
        )
    ]

    result = correlate(findings)

    assert len(result) == 0


def test_multiple_url_signals():
    findings = [
        Finding(id="BRAND_IMPERSONATION", source="url", description="Brand", points=25),
        Finding(id="IP_BASED_URL", source="url", description="IP", points=20),
        Finding(id="LONG_URL", source="url", description="Long", points=10)
    ]

    result = correlate(findings)

    correlation_ids = [finding.id for finding in result]

    assert "BRAND_AND_IP_URL" in correlation_ids
    assert "MULTIPLE_URL_SIGNALS" in correlation_ids