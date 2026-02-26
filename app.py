from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from parser import parse_requirements
from risk_engine import calculate_risk
from relation_engine import analyze_dependency_relations
from attack_simulator import simulate_attack
from tag_engine import generate_tags
from url_scanner import scan_general_url

import os
import requests
import io
import re
import socket
from urllib.parse import urlparse

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

latest_results = []
latest_summary = {"low": 0, "medium": 0, "high": 0}


# ------------------------------------
# Utility Functions
# ------------------------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_release_year(package_name):
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=3)

        if response.status_code == 200:
            data = response.json()
            latest_version = data["info"]["version"]
            release_info = data["releases"].get(latest_version, [])

            if release_info:
                upload_time = release_info[0]["upload_time"]
                return upload_time[:4]
    except:
        pass

    return "Unknown"


# ------------------------------------
# Main Dashboard Route
# ------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results, latest_summary

    results = []
    summary = {"low": 0, "medium": 0, "high": 0}

    if request.method == "POST":

        file = request.files.get("file")
        url_input = request.form.get("url")
        hash_value = request.form.get("hash")

        # ================= FILE SCAN =================
        if file and allowed_file(file.filename):

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            dependencies = parse_requirements(filepath)

            if dependencies:

                results = calculate_risk(dependencies)
                relation_data = analyze_dependency_relations(dependencies)

                for r in results:

                    r["type"] = "Dependency"
                    r["title"] = r.get("name")

                    # Add relation impact
                    r["relations"] = relation_data.get(
                        r["name"],
                        {"impact_level": "Low", "centrality_score": 0}
                    )

                    if r["relations"]["impact_level"] == "Critical":
                        r["score"] = min(r["score"] + 10, 100)

                    # Add release year
                    r["release_year"] = get_release_year(r["name"])

                    # Attack simulation
                    r["simulation"] = simulate_attack(
                        r["name"],
                        risk_score=r["score"]
                    )

                    # Tags
                    r["tags"] = generate_tags(
                        r["name"],
                        r["score"],
                        r["release_year"]
                    )

        # ================= URL SCAN =================
        elif url_input and url_input.startswith(("http://", "https://")):

            url_result = scan_general_url(url_input)

            results = [{
                "type": "URL",
                "title": url_input,
                "risk": url_result.get("risk", "Low"),
                "score": url_result.get("score", 0),
                "details": url_result.get("details", []),
                "recommendation": "Verify HTTPS and inspect suspicious keywords",
                "threat_intel": {"cvss_score": 0},
                "ai_explanation": ""
            }]

        # ================= HASH SCAN =================
        elif hash_value:

            hash_risk = "Low"
            score = 10
            details = ["Basic hash pattern analysis"]

            if re.fullmatch(r"[A-Fa-f0-9]{64}", hash_value):
                hash_risk = "High"
                score = 75
                details.append("SHA256 hash pattern detected")

            elif re.fullmatch(r"[A-Fa-f0-9]{40}", hash_value):
                hash_risk = "Medium"
                score = 40
                details.append("SHA1 hash pattern detected")

            results = [{
                "type": "Hash",
                "title": hash_value,
                "risk": hash_risk,
                "score": score,
                "details": details,
                "recommendation": "Investigate hash origin if suspicious",
                "threat_intel": {"cvss_score": 0},
                "ai_explanation": ""
            }]

        # 🔐 Ensure consistent structure for ALL results
        for r in results:
            r.setdefault("ai_explanation", "")
            r.setdefault("threat_intel", {"cvss_score": 0})

        # Summary calculation
        summary = {
            "low": sum(1 for r in results if r["risk"] == "Low"),
            "medium": sum(1 for r in results if r["risk"] == "Medium"),
            "high": sum(1 for r in results if r["risk"] == "High"),
        }

        latest_results = results
        latest_summary = summary

    return render_template("index.html", results=results, summary=summary)


# ------------------------------------
# Download Report
# ------------------------------------

@app.route("/download-report")
def download_report():
    global latest_results, latest_summary

    if not latest_results:
        return "No scan data available."

    report_text = "DEPENDENCY-GUARD SECURITY REPORT\n"
    report_text += "=====================================\n\n"

    report_text += f"Low Risk: {latest_summary['low']}\n"
    report_text += f"Medium Risk: {latest_summary['medium']}\n"
    report_text += f"High Risk: {latest_summary['high']}\n\n"

    for r in latest_results:
        report_text += f"\nTarget: {r.get('title')}\n"
        report_text += f"Risk: {r['risk']} ({r['score']}%)\n"

        cvss = r.get("threat_intel", {}).get("cvss_score", 0)
        report_text += f"CVSS Score: {cvss}\n"

        for d in r.get("details", []):
            report_text += f"- {d}\n"

        if r.get("ai_explanation"):
            report_text += "\nAI Risk Analysis:\n"
            report_text += r["ai_explanation"] + "\n"

        if r.get("recommendation"):
            report_text += f"\nRecommendation: {r['recommendation']}\n"

        report_text += "\n----------------------------------------\n"

    file_stream = io.BytesIO()
    file_stream.write(report_text.encode("utf-8"))
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name="Dependency_Guard_Report.txt",
        mimetype="text/plain"
    )


# ------------------------------------
# Run App
# ------------------------------------

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)