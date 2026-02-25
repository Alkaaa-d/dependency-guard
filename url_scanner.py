import requests
import re


def scan_general_url(url):

    result = {
        "type": "URL",
        "target": url,
        "score": 0,
        "risk": "Low",
        "details": []
    }

    try:
        response = requests.get(url, timeout=5)

        if not url.startswith("https"):
            result["score"] += 15
            result["details"].append("Not using HTTPS")

        suspicious_keywords = ["login", "verify", "password", "bank"]

        for keyword in suspicious_keywords:
            if re.search(keyword, response.text, re.IGNORECASE):
                result["score"] += 20
                result["details"].append(f"Suspicious keyword: {keyword}")
                break

        if result["score"] >= 60:
            result["risk"] = "High"
        elif result["score"] >= 30:
            result["risk"] = "Medium"

    except:
        result["risk"] = "High"
        result["score"] = 80
        result["details"].append("URL unreachable")

    return result