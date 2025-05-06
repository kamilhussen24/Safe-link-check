import requests
import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://safe-link-check.vercel.app"])

@app.route('/api/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({"status": "error", "message": "Missing 'url' in request."}), 400

        url = data["url"].strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            return jsonify({"status": "error", "message": "Please enter a valid URL (must start with http or https)."}), 400

        api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
        if not api_key:
            return jsonify({"status": "error", "message": "Server misconfiguration. API key is missing."}), 500

        print(f"[CHECKING] URL received: {url}")

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
            print(f"[DANGER] Unsafe URL detected: {url}")
            return jsonify({
                "status": "danger",
                "message": "⚠️ This link is flagged as dangerous. Avoid clicking!",
                "details": result["matches"]
            }), 200

        print(f"[SAFE] URL is clean: {url}")
        return jsonify({
            "status": "safe",
            "message": "✅ This link appears safe and secure.",
            "url": url
        }), 200

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API call failed: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to reach Safe Browsing API."}), 502

    except Exception as e:
        print(f"[ERROR] Unexpected server error: {str(e)}")
        return jsonify({"status": "error", "message": "Server error. Try again later."}), 500


if __name__ == "__main__":
    app.run()
