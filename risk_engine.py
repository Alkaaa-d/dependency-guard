import requests


# -------------------------------------
# OSV Threat Intelligence
# -------------------------------------
def get_osv_details(package, version):

    if not package or not version:
        return {
            "count": 0,
            "cves": [],
            "severity": "Low",
            "cvss_score": 0
        }

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

        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])

            severity_scores = []
            cve_ids = []

            for v in vulns:

                if "id" in v:
                    cve_ids.append(v["id"])

                if "severity" in v:
                    for s in v["severity"]:
                        score = s.get("score")
                        if score:
                            try:
                                severity_scores.append(float(score))
                            except:
                                pass

                if "database_specific" in v:
                    db = v.get("database_specific", {})
                    cvss = db.get("cvss")

                    if isinstance(cvss, dict):
                        score = cvss.get("score")
                        if score:
                            try:
                                severity_scores.append(float(score))
                            except:
                                pass

                if "cvss" in v:
                    cvss = v.get("cvss")
                    if isinstance(cvss, dict):
                        score = cvss.get("score")
                        if score:
                            try:
                                severity_scores.append(float(score))
                            except:
                                pass

            max_score = max(severity_scores) if severity_scores else 0

            if max_score >= 9:
                severity_level = "Critical"
            elif max_score >= 7:
                severity_level = "High"
            elif max_score >= 4:
                severity_level = "Medium"
            else:
                severity_level = "Low"

            return {
                "count": len(vulns),
                "cves": cve_ids,
                "severity": severity_level,
                "cvss_score": round(max_score, 1)
            }

    except Exception as e:
        print("OSV error:", e)

    return {
        "count": 0,
        "cves": [],
        "severity": "Low",
        "cvss_score": 0
    }


# -------------------------------------
# AI-Based Risk Explanation
# -------------------------------------
def generate_ai_explanation(name, score, risk, reasons, threat_intel):

    explanation = []

    vuln_count = threat_intel.get("count", 0)
    severity = threat_intel.get("severity", "Low")
    cvss = threat_intel.get("cvss_score", 0)

    explanation.append(f"Dependency '{name}' security analysis summary:")

    if vuln_count > 0:
        explanation.append(
            f"It contains {vuln_count} known vulnerabilities "
            f"(highest CVSS score: {cvss}, Severity: {severity})."
        )
    else:
        explanation.append("No publicly disclosed vulnerabilities detected.")

    if score >= 80:
        explanation.append(
            "The overall risk score is critically high due to multiple security risks."
        )
    elif score >= 40:
        explanation.append(
            "The package presents moderate security concerns."
        )
    else:
        explanation.append(
            "The package currently demonstrates low observable risk."
        )

    if "Not using latest version" in reasons:
        explanation.append(
            "The installed version is outdated."
        )

    if "Old major version detected" in reasons:
        explanation.append(
            "The major version is significantly old."
        )

    if risk == "High":
        recommendation = "Immediate upgrade recommended."
    elif risk == "Medium":
        recommendation = "Upgrade soon."
    else:
        recommendation = "Continue monitoring."

    explanation.append("Recommendation: " + recommendation)

    return " ".join(explanation)


# -------------------------------------
# Main Risk Calculation
# -------------------------------------
def calculate_risk(dependencies):

    results = []

    for dep in dependencies:

        score = 0
        reasons = []

        name = dep.get("name", "").strip()
        raw_version = str(dep.get("version", "")).strip()
        version = raw_version.replace("==", "").strip()

        if not name:
            continue

        osv_data = get_osv_details(name, version)

        vuln_count = osv_data["count"]
        severity = osv_data["severity"]

        if vuln_count > 0:
            score += min(60, vuln_count * 15)
            reasons.append(f"{vuln_count} known vulnerabilities found")

        if severity == "Critical":
            score += 30
        elif severity == "High":
            score += 20
        elif severity == "Medium":
            score += 10

        if version.startswith(("0.", "1.")):
            score += 20
            reasons.append("Old major version detected")

        try:
            url = f"https://pypi.org/pypi/{name}/json"
            response = requests.get(url, timeout=3)

            if response.status_code == 200:
                data = response.json()
                latest_version = data["info"]["version"]

                if latest_version.strip() != version.strip():
                    score += 10
                    reasons.append("Not using latest version")

        except Exception as e:
            print("PyPI check error:", e)

        score = min(score, 100)

        if score >= 80:
            risk = "High"
        elif score >= 40:
            risk = "Medium"
        else:
            risk = "Low"

        recommendation = (
            "Immediate upgrade required"
            if risk == "High"
            else "Consider updating package"
            if risk == "Medium"
            else "Safe to use"
        )

        ai_summary = generate_ai_explanation(
            name, score, risk, reasons, osv_data
        )

        results.append({
            "type": "Dependency",
            "name": name,
            "version": version,
            "score": score,
            "risk": risk,
            "details": reasons,
            "threat_intel": osv_data,
            "recommendation": recommendation,
            "ai_explanation": ai_summary
        })

    return results