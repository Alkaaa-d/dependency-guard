import requests
import re

VT_API_KEY = "7bef50e5abc9ec09c2e16c826f07ef7918e77c477f1603cbe26eebe6ada01fbbE"

def check_virustotal(url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}

    # Submit URL for scan
    response = requests.post(vt_url, headers=headers, data={"url": url})

    if response.status_code != 200:
        return 0, []

    analysis_id = response.json()["data"]["id"]

    # Get analysis result
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report = requests.get(report_url, headers=headers)

    if report.status_code != 200:
        return 0, []

    stats = report.json()["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    score = malicious * 15 + suspicious * 8
    details = []

    if malicious:
        details.append(f"Detected malicious by {malicious} engines")
    if suspicious:
        details.append(f"Suspicious by {suspicious} engines")

    return score, details


def scan_general_url(url):

    result = {
        "type": "URL",
        "target": url,
        "score": 0,
        "risk": "Low",
        "details": []
    }

    # -------------------------
    # Heuristic checks (your old)
    # -------------------------
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

    except:
        result["score"] += 40
        result["details"].append("URL unreachable")

    # -------------------------
    # VirusTotal check
    # -------------------------
    try:
        vt_score, vt_details = check_virustotal(url)
        result["score"] += vt_score
        result["details"].extend(vt_details)
    except:
        result["details"].append("VirusTotal lookup failed")

    # -------------------------
    # Risk classification
    # -------------------------
    if result["score"] >= 70:
        result["risk"] = "High"
    elif result["score"] >= 35:
        result["risk"] = "Medium"
    else:
        result["risk"] = "Low"

    return result