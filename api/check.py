import requests
import os
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.json
    url = data.get("url")
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

    response = requests.post(endpoint, json=payload)
    result = response.json()

    if "matches" in result:
        return jsonify({"status": "danger", "message": "⚠️ Unsafe URL detected!"})
    return jsonify({"status": "safe", "message": "✅ URL is safe."})

if __name__ == "__main__":
    app.run()
