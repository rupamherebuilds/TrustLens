import dns.resolver
import ipaddress

from core.models import Finding, ModuleResult, ScanContext


def get_dns_records(domain):
    records = {}
    errors = {}

    for record_type in ["A", "AAAA", "MX", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            errors[record_type] = "Domain does not exist"

        except dns.resolver.NoAnswer:
            records[record_type] = []
            errors[record_type] = "No records of this type"

        except dns.resolver.LifetimeTimeout:
            records[record_type] = []
            errors[record_type] = "DNS lookup timed out"

        except dns.resolver.NoNameservers:
            records[record_type] = []
            errors[record_type] = "No nameservers available"

    return records, errors


def get_domain_ips(records):
    ips = []

    for record_type in ["A", "AAAA"]:
        for address in records.get(record_type, []):
            try:
                ipaddress.ip_address(address)
                ips.append(address)
            except ValueError:
                continue

    return list(set(ips))


def analyze_domain(domain):
    findings = []
    records, errors = get_dns_records(domain)

    ips = get_domain_ips(records)

    if not any(records.values()):
        findings.append(
            Finding(
                id="NO_DNS_RECORDS",
                source="domain",
                description="The domain has no available DNS records.",
                points=20,
                data={"domain": domain}
            )
        )

    return findings, records, ips, errors


async def run(ctx: ScanContext) -> ModuleResult:
    domain = ctx.registered_domain or ctx.host

    findings, records, ips, errors = analyze_domain(domain)

    ctx.facts["domain"] = {
        "records": records,
        "ips": ips,
        "errors": errors
    }

    return ModuleResult(
        module="domain",
        status="success",
        findings=findings
    )