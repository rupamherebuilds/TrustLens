from modules.url import analyze_url

url = "https://paypal.com.evil.org/login"

findings = analyze_url(url)

print("Total findings:", len(findings))

for finding in findings:
    print("\nID:", finding.id)
    print("Source:", finding.source)
    print("Description:", finding.description)
    print("Points:", finding.points)
    print("Data:", finding.data)