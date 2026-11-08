import json
from pathlib import Path


BRANDS_FILE = Path("data/brands.json")

with BRANDS_FILE.open("r", encoding="utf-8") as file:
    brands = json.load(file)


print("Total brands:", len(brands))

for brand in brands:
    print(brand["brand"], "->", brand["domain"])