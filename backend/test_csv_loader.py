import csv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR / "data" / "test_links.csv"


def load_test_links():
    with CSV_FILE.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        test_links = list(reader)

    return test_links


if __name__ == "__main__":
    links = load_test_links()

    print("Total test links:", len(links))
    print()

    for link in links:
        print("URL:", link["url"])
        print("Expected:", link["expected_label"])
        print("Category:", link["category"])
        print("-" * 40)