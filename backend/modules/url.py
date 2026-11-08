from urllib.parse import urlparse
import tldextract


def normalize_url(url: str) -> dict:

    parsed = urlparse(url)

    extracted = tldextract.extract(url)

    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "subdomain": extracted.subdomain,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "registered_domain": extracted.top_domain_under_public_suffix,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "port": parsed.port,
    }

import json
import ipaddress
from pathlib import Path

from core.models import Finding, ModuleResult, ScanContext


BASE_DIR = Path(__file__).resolve().parent.parent
BRANDS_FILE = BASE_DIR / "data" / "brands.json"


def load_brands():
    with BRANDS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def check_ip_address(hostname: str | None) -> bool:
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_at_symbol(url: str) -> bool:
    parsed = urlparse(url)

    return parsed.username is not None or parsed.password is not None


def check_long_url(url: str) -> bool:
    return len(url) > 100


def check_many_subdomains(subdomain: str) -> bool:
    if not subdomain:
        return False

    return len(subdomain.split(".")) >= 3


def check_punycode(hostname: str | None) -> bool:
    if not hostname:
        return False

    return "xn--" in hostname.lower()


def check_suspicious_brand(hostname: str | None) -> list[str]:
    if not hostname:
        return []

    hostname = hostname.lower()
    brands = load_brands()

    suspicious_brands = []

    for brand in brands:
        brand_domain = brand["domain"].lower()
        brand_name = brand["brand"].lower()

        if brand_domain in hostname and hostname != brand_domain:
            suspicious_brands.append(brand_name)

    return suspicious_brands


def analyze_url(url: str) -> list[Finding]:

    findings = []

    info = normalize_url(url)

    hostname = info["hostname"]
    subdomain = info["subdomain"]

    if check_ip_address(hostname):
        findings.append(
            Finding(
                id="IP_BASED_URL",
                source="url",
                description="URL uses an IP address instead of a domain name.",
                points=20,
            )
        )

    if check_at_symbol(url):
        findings.append(
            Finding(
                id="URL_AT_SYMBOL",
                source="url",
                description="URL contains username or password information before the hostname.",
                points=20,
            )
        )

    if check_long_url(url):
        findings.append(
            Finding(
                id="LONG_URL",
                source="url",
                description="URL is unusually long.",
                points=10,
            )
        )

    if check_many_subdomains(subdomain):
        findings.append(
            Finding(
                id="EXCESSIVE_SUBDOMAINS",
                source="url",
                description="URL contains an unusually high number of subdomains.",
                points=15,
            )
        )

    if check_punycode(hostname):
        findings.append(
            Finding(
                id="PUNYCODE_DOMAIN",
                source="url",
                description="URL contains a punycode-encoded hostname.",
                points=20,
            )
        )

    suspicious_brands = check_suspicious_brand(hostname)

    if suspicious_brands:
        findings.append(
            Finding(
                id="BRAND_IMPERSONATION",
                source="url",
                description="URL hostname contains a known brand domain as part of a suspicious hostname.",
                points=25,
                data={"brands": suspicious_brands},
            )
        )

    return findings


async def run(ctx: ScanContext) -> ModuleResult:

    findings = analyze_url(ctx.url)

    result = ModuleResult(
        module="url",
        status="success",
        findings=findings,
    )

    return result