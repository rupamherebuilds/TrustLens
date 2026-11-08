import asyncio

from core.models import ScanContext
from modules.url import run


async def main():

    ctx = ScanContext(
        scan_id="test-001",
        url="https://paypal.com.evil.org/login",
        host="paypal.com.evil.org",
    )

    result = await run(ctx)

    print("Module:", result.module)
    print("Status:", result.status)
    print("Total findings:", len(result.findings))

    for finding in result.findings:
        print("\nFinding ID:", finding.id)
        print("Points:", finding.points)
        print("Data:", finding.data)


asyncio.run(main())