from modules.url import (
    check_ip_address,
    check_at_symbol,
    check_long_url,
    check_many_subdomains,
    check_punycode,
    check_suspicious_brand,
)


print("IP:", check_ip_address("192.168.1.1"))

print("AT:", check_at_symbol("https://paypal.com@evil.com"))

print("LONG:", check_long_url("https://example.com/" + "a" * 120))

print("SUBDOMAINS:", check_many_subdomains("a.b.c.example"))

print("PUNYCODE:", check_punycode("xn--pple-43d.com"))

print("BRAND:", check_suspicious_brand("paypal.com.evil.org"))