from core.models import ScanContext, Finding, ModuleResult


ctx = ScanContext(
    scan_id="test-001",
    url="https://example.com",
    host="example.com"
)

finding = Finding(
    id="VERY_NEW_DOMAIN",
    source="domain",
    description="Domain is newly registered",
    points=25
)

result = ModuleResult(
    module="domain",
    findings=[finding]
)

print(ctx)
print(finding)
print(result)

print("Models working successfully!")