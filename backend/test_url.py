from modules.url import normalize_url


url = "https://login.example.com/dashboard?id=10"

result = normalize_url(url)

for key, value in result.items():
    print(f"{key}: {value}")