import dns.resolver

from modules.domain import get_dns_records, get_domain_ips
from modules.domain import analyze_domain


def test_get_dns_records_success(monkeypatch):
    def fake_resolve(domain, record_type):
        if record_type == "A":
            return ["142.250.183.14"]

        if record_type == "AAAA":
            return ["2607:f8b0:4004:c1b::64"]

        if record_type == "MX":
            return ["10 mail.example.com"]

        if record_type == "NS":
            return ["ns1.example.com"]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    records, errors = get_dns_records("example.com")

    assert records["A"] == ["142.250.183.14"]
    assert records["AAAA"] == ["2607:f8b0:4004:c1b::64"]
    assert records["MX"] == ["10 mail.example.com"]
    assert records["NS"] == ["ns1.example.com"]
    assert errors == {}


def test_get_domain_ips():
    records = {
        "A": ["142.250.183.14"],
        "AAAA": ["2607:f8b0:4004:c1b::64"],
        "MX": [],
        "NS": []
    }

    ips = get_domain_ips(records)

    assert "142.250.183.14" in ips
    assert "2607:f8b0:4004:c1b::64" in ips
    assert len(ips) == 2

def test_get_dns_records_nxdomain(monkeypatch):
    def fake_resolve(domain, record_type):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    records, errors = get_dns_records("fake-domain.example")

    assert records["A"] == []
    assert records["AAAA"] == []
    assert records["MX"] == []
    assert records["NS"] == []

    assert errors["A"] == "Domain does not exist"

def test_analyze_domain_without_dns_records(monkeypatch):
    def fake_get_dns_records(domain):
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": []
        }

        errors = {
            "A": "Domain does not exist"
        }

        return records, errors

    monkeypatch.setattr(
        "modules.domain.get_dns_records",
        fake_get_dns_records
    )

    findings, records, ips, errors = analyze_domain("fake-domain.example")

    assert len(findings) == 1
    assert findings[0].id == "NO_DNS_RECORDS"
    assert findings[0].points == 20
    assert ips == []