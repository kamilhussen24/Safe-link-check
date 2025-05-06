import requests
import os
import json

def handler(request):
    try:
        if request.method != "POST":
            return {
                "statusCode": 405,
                "body": "Only POST allowed"
            }

        body = request.get_json()
        url = body.get("url")
        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

        payload = {
            "client": {"clientId": "kamil-checker", "clientVersion": "1.0"},
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
            return {
                "statusCode": 200,
                "body": "⚠️ Unsafe URL detected!"
            }
        else:
            return {
                "statusCode": 200,
                "body": "✅ URL looks safe!"
            }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error: {str(e)}"
        }
