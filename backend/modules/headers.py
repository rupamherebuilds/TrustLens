import httpx
import socket
import ipaddress
from urllib.parse import urlparse

from core.models import Finding, ModuleResult, ScanContext

def assert_public(hostname):
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False

        return True

    except (socket.gaierror, ValueError, OSError):
        return False

async def fetch_headers(url):
    current_url = url

    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=False
    ) as client:

        for _ in range(4):
            parsed_url = urlparse(current_url)
            hostname = parsed_url.hostname

            if parsed_url.scheme not in ("http", "https"):
                return None

            if not hostname or not assert_public(hostname):
                return None

            try:
                response = await client.get(current_url)

            except httpx.RequestError:
                return None

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")

                if not location:
                    return None

                current_url = str(response.url.join(location))
                continue

            return response.headers

    return None


def findings_from_headers(headers, url):
    findings = []

    if url.startswith("http://"):
        findings.append(
            Finding(
                id="INSECURE_HTTP",
                source="headers",
                description="The URL uses insecure HTTP instead of HTTPS.",
                points=20
            )
        )

    if "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="MISSING_HSTS",
                source="headers",
                description="The website does not use HTTP Strict Transport Security.",
                points=10
            )
        )

    if "content-security-policy" not in headers:
        findings.append(
            Finding(
                id="MISSING_CSP",
                source="headers",
                description="The website does not have a Content Security Policy.",
                points=10
            )
        )

    if (
        "x-frame-options" not in headers
        and "frame-ancestors" not in headers.get("content-security-policy", "")
    ):
        findings.append(
            Finding(
                id="MISSING_FRAME_PROTECTION",
                source="headers",
                description="The website does not have frame protection.",
                points=10
            )
        )

    return findings

async def run(ctx: ScanContext) -> ModuleResult:
    findings = []

    headers = await fetch_headers(ctx.url)

    if headers is None:
        return ModuleResult(
            module="headers",
            status="failed",
            findings=[],
            error="Could not safely fetch HTTP headers."
        )

    findings = findings_from_headers(headers, ctx.url)

    ctx.facts["headers"] = dict(headers)

    return ModuleResult(
        module="headers",
        status="success",
        findings=findings
    )