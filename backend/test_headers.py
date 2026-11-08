import asyncio

from modules.headers import run
from core.models import ScanContext


async def main():
    test_urls = [
        "https://google.com",
        "https://github.com",
        "https://example.com",
        "http://localhost",
        "http://192.168.1.1"
    ]

    for index, url in enumerate(test_urls, start=1):
        ctx = ScanContext(
            scan_id=f"headers-test-{index}",
            url=url,
            host=url.split("/")[2].split(":")[0]
        )

        result = await run(ctx)

        print("\nURL:", url)
        print("Module Status:", result.status)
        print("Error:", result.error)
        print("Findings:", [finding.id for finding in result.findings])

        print("-" * 50)


if __name__ == "__main__":
    asyncio.run(main())