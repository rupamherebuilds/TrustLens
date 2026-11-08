import asyncio

from modules.domain import run
from core.models import ScanContext


async def main():
    test_domains = [
        "google.com",
        "github.com",
        "example.com",
        "this-domain-does-not-exist-123456789.com"
    ]

    for index, domain in enumerate(test_domains, start=1):
        ctx = ScanContext(
            scan_id=f"domain-test-{index}",
            url=f"https://{domain}",
            host=domain,
            registered_domain=domain
        )

        result = await run(ctx)

        print("\nDomain:", domain)
        print("Status:", result.status)
        print("Findings:", [finding.id for finding in result.findings])
        print("DNS Records:", ctx.facts["domain"]["records"])
        print("IP Addresses:", ctx.facts["domain"]["ips"])
        print("DNS Errors:", ctx.facts["domain"]["errors"])
        print("-" * 50)


if __name__ == "__main__":
    asyncio.run(main())