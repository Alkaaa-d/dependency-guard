import pandas as pd
import os
import requests   # ✅ NEW

# ✅ NEW FUNCTION (REAL VULNERABILITY CHECK)
def check_real_vulnerability(package, version):
    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        data = response.json()
        return len(data.get("vulns", []))
    except:
        return 0


def calculate_risk(dependencies):
    # Safe CSV path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, "data", "vulnerability.csv")

    try:
        vuln_data = pd.read_csv(csv_path)
    except Exception as e:
        print("Error loading vulnerability data:", e)
        vuln_data = pd.DataFrame(columns=["package", "risk"])

    results = []

    for dep in dependencies:
        score = 0
        reasons = []
        breakdown = {
            "vulnerability": 0,
            "version_age": 0,
            "trust": 0
        }

        # 1️⃣ REAL OSV Vulnerability Check (NEW)
        real_vulns = check_real_vulnerability(dep["name"], dep["version"])

        if real_vulns > 0:
            breakdown["vulnerability"] = 50
            reasons.append(f"{real_vulns} real vulnerabilities found (OSV)")

        else:
            # Fallback to CSV demo logic if no real vuln found
            match = vuln_data[
                vuln_data["package"].str.lower() == dep["name"].lower()
            ]

            if not match.empty:
                risk = match.iloc[0]["risk"].lower()

                if risk == "high":
                    breakdown["vulnerability"] = 50
                    reasons.append("Known high-severity vulnerability")
                elif risk == "medium":
                    breakdown["vulnerability"] = 30
                    reasons.append("Moderate vulnerability history")
                else:
                    breakdown["vulnerability"] = 10

        # 2️⃣ Version age factor
        if dep["version"].startswith(("1.", "2.")):
            breakdown["version_age"] = 20
            reasons.append("Outdated version")

        # 3️⃣ Trust heuristic
        if dep["name"].lower() == "log4j":
            breakdown["trust"] = 20
            reasons.append("Low maintainer trust")

        # Final score
        score = sum(breakdown.values())

        # Risk classification
        if score >= 70:
            risk_level = "High"
        elif score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Recommendation
        if risk_level == "High":
            recommendation = "Update or replace immediately"
        elif risk_level == "Medium":
            recommendation = "Update to latest version"
        else:
            recommendation = "Safe to use"

        results.append({
            "name": dep["name"],
            "version": dep["version"],
            "score": score,
            "risk": risk_level,
            "reason": ", ".join(reasons),
            "breakdown": breakdown,
            "recommendation": recommendation
        })

    return results
