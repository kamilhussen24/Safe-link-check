import requests
import os

def handler(request):
    body = request.get_json()
    url = body.get("url")

    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {
            "clientId": "kamil-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(endpoint, json=payload)
    data = res.json()

    if "matches" in data:
        return {"statusCode": 200, "body": "⚠️ Unsafe URL Detected!"}
    else:
        return {"statusCode": 200, "body": "✅ This URL is safe."}
