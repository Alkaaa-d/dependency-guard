import requests
from datetime import datetime


# -------------------------------------
# OSV Vulnerability Check
# -------------------------------------
def check_osv_vulnerabilities(package, version):

    url = "https://api.osv.dev/v1/query"

    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(url, json=payload, timeout=3)

        if response.status_code == 200:
            data = response.json()
            return len(data.get("vulns", []))

    except:
        pass

    return 0


# -------------------------------------
# Main Risk Calculation
# -------------------------------------
def calculate_risk(dependencies):

    results = []

    for dep in dependencies:

        score = 0
        reasons = []

        breakdown = {
            "vulnerability": 0,
            "version_age": 0,
            "trust": 0,
            "maintenance": 0
        }

        name = dep.get("name", "")
        version = dep.get("version", "")

        # -----------------------------
        # 1️⃣ Real Vulnerability Check
        # -----------------------------
        vuln_count = check_osv_vulnerabilities(name, version)

        if vuln_count > 0:
            vuln_score = min(60, vuln_count * 20)
            breakdown["vulnerability"] = vuln_score
            score += vuln_score
            reasons.append(f"{vuln_count} known vulnerabilities detected")

        # -----------------------------
        # 2️⃣ Version Age Check
        # -----------------------------
        if version.startswith(("0.", "1.")):
            breakdown["version_age"] = 25
            score += 25
            reasons.append("Very old major version")

        elif version.startswith("2."):
            breakdown["version_age"] = 15
            score += 15
            reasons.append("Outdated major version")

        # -----------------------------
        # 3️⃣ Known Risky Packages
        # -----------------------------
        risky_packages = ["log4j", "event-stream"]

        if name.lower() in risky_packages:
            breakdown["trust"] = 25
            score += 25
            reasons.append("Historically compromised package")

        # -----------------------------
        # 4️⃣ Maintenance Check
        # -----------------------------
        try:
            url = f"https://pypi.org/pypi/{name}/json"
            response = requests.get(url, timeout=3)

            if response.status_code == 200:
                data = response.json()
                latest_version = data["info"]["version"]
                release_info = data["releases"].get(latest_version, [])

                if release_info:
                    upload_time = release_info[0]["upload_time"]
                    release_year = int(upload_time[:4])
                    current_year = datetime.now().year

                    if current_year - release_year >= 3:
                        breakdown["maintenance"] = 20
                        score += 20
                        reasons.append("Inactive or poorly maintained package")

        except:
            pass

        # -----------------------------
        # Final Risk Level
        # -----------------------------
        if score >= 75:
            risk = "High"
        elif score >= 40:
            risk = "Medium"
        else:
            risk = "Low"

        # -----------------------------
        # Recommendation
        # -----------------------------
        if risk == "High":
            recommendation = "Immediate upgrade or replacement required"
        elif risk == "Medium":
            recommendation = "Update to latest stable version"
        else:
            recommendation = "Safe to use"

        # -----------------------------
        # Append Result
        # -----------------------------
        results.append({
            "type": "Dependency",
            "name": name,
            "version": version,
            "score": min(score, 100),
            "risk": risk,
            "reason": ", ".join(reasons) if reasons else "No major issues detected",
            "breakdown": breakdown,
            "recommendation": recommendation
        })

    return results