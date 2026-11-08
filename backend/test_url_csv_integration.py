import asyncio
from test_csv_loader import load_test_links
from modules.url import run
from core.models import ScanContext


async def main():
    test_links = load_test_links()
    passed = 0
    failed = 0

    print("\n========== TRUSTLENS URL TESTING ==========\n")

    for index, link in enumerate(test_links, start=1):
        ctx = ScanContext(
            scan_id=f"test-{index}",
            url=link["url"],
            host=link["url"].split("/")[2].split(":")[0]
        )

        result = await run(ctx)

        actual_label = "suspicious" if result.findings else "safe"
        expected_label = link["expected_label"]

        if actual_label == expected_label:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1

        print("URL:", link["url"])
        print("Expected:", expected_label)
        print("Actual:", actual_label)
        print("Findings:", len(result.findings))
        print("Status:", status)
        print("-" * 45)

    print("\n========== TEST SUMMARY ==========")
    print("Total Tests:", len(test_links))
    print("Passed:", passed)
    print("Failed:", failed)


if __name__ == "__main__":
    asyncio.run(main())