from core.models import Finding
from core.correlate import correlate


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
        description="URL uses an IP address.",
        points=20
    ),
    Finding(
        id="LONG_URL",
        source="url",
        description="URL is unusually long.",
        points=10
    )
]

correlated_findings = correlate(findings)

print("Original Findings:")
for finding in findings:
    print(finding.id)

print("\nCorrelated Findings:")
for finding in correlated_findings:
    print(finding.id)
    print("Source:", finding.source)
    print("Points:", finding.points)
    print("Related:", finding.data["related_findings"])

    print("\n========== NEGATIVE TEST ==========")

safe_findings = [
    Finding(
        id="LONG_URL",
        source="url",
        description="URL is unusually long.",
        points=10
    )
]

safe_correlated = correlate(safe_findings)

print("Input Findings:", [finding.id for finding in safe_findings])
print("Correlated Findings:", [finding.id for finding in safe_correlated])

if not safe_correlated:
    print("Result: PASS")
else:
    print("Result: FAIL")


print("\n========== DUPLICATE TEST ==========")

duplicate_findings = [
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
    ),
    Finding(
        id="IP_BASED_URL",
        source="url",
        description="IP based URL detected again.",
        points=20
    )
]

duplicate_correlated = correlate(duplicate_findings)

correlation_ids = [finding.id for finding in duplicate_correlated]

print("Correlated Findings:", correlation_ids)

if len(correlation_ids) == len(set(correlation_ids)):
    print("Result: PASS")
else:
    print("Result: FAIL")