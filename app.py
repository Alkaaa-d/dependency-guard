from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
from parser import parse_requirements
from risk_engine import calculate_risk
from attack_simulator import simulate_attack   # ✅ NEW IMPORT
import os
import requests
from datetime import datetime
import io

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

latest_results = []
latest_summary = {"low": 0, "medium": 0, "high": 0}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_release_year(package_name):
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            latest_version = data["info"]["version"]

            if latest_version in data["releases"]:
                release_info = data["releases"][latest_version]
                if release_info:
                    upload_time = release_info[0]["upload_time"]
                    return upload_time[:4]

        return "Unknown"
    except:
        return "Unknown"


@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results, latest_summary

    results = []
    summary = {"low": 0, "medium": 0, "high": 0}

    if request.method == "POST":
        file = request.files.get("file")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            dependencies = parse_requirements(filepath)

            # 🔥 Your existing risk engine
            results = calculate_risk(dependencies)

            for r in results:
                # Add release year
                r["release_year"] = get_release_year(r["name"])

                # 🔥 ADD ATTACK SIMULATION HERE
                r["simulation"] = simulate_attack(
                    r["name"],
                    risk_score=r["score"]
                )

                # Progress bar class
                if r["score"] > 75:
                    r["progress_class"] = "critical"
                elif r["score"] > 50:
                    r["progress_class"] = "high"
                elif r["score"] > 20:
                    r["progress_class"] = "medium"
                else:
                    r["progress_class"] = "low"

            summary = {
                "low": sum(1 for r in results if r["risk"] == "Low"),
                "medium": sum(1 for r in results if r["risk"] == "Medium"),
                "high": sum(1 for r in results if r["risk"] == "High"),
            }

            latest_results = results
            latest_summary = summary

    return render_template(
        "index.html",
        results=results,
        summary=summary
    )


@app.route("/download-report")
def download_report():
    global latest_results, latest_summary

    if not latest_results:
        return "No scan data available. Please scan dependencies first."

    report_text = "DEPENDENCY-GUARD SECURITY REPORT\n"
    report_text += "=====================================\n\n"

    report_text += "SUMMARY\n"
    report_text += f"Low Risk: {latest_summary['low']}\n"
    report_text += f"Medium Risk: {latest_summary['medium']}\n"
    report_text += f"High Risk: {latest_summary['high']}\n\n"

    report_text += "DEPENDENCY DETAILS\n"
    report_text += "-------------------------------------\n"

    for r in latest_results:
        report_text += f"Package: {r['name']}\n"
        report_text += f"Version: {r['version']}\n"
        report_text += f"Release Year: {r['release_year']}\n"
        report_text += f"Risk Score: {r['score']}\n"
        report_text += f"Risk Level: {r['risk']}\n"
        report_text += f"Vulnerability: {r['breakdown']['vulnerability']}\n"
        report_text += f"Trust Level: {r['breakdown']['trust']}\n"
        report_text += f"Reason: {r['reason']}\n"
        report_text += f"Recommendation: {r['recommendation']}\n"

        # 🔥 ADD ATTACK SIMULATION TO REPORT
        if "simulation" in r:
            report_text += f"Impact Level: {r['simulation']['impact_level']}\n"
            report_text += "Simulated Attacks:\n"
            for attack in r["simulation"]["simulated_attacks"]:
                report_text += f" - {attack}\n"

        report_text += "-------------------------------------\n"

    report_text += "\nReport Generated On: "
    report_text += datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_stream = io.BytesIO()
    file_stream.write(report_text.encode("utf-8"))
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name="Dependency_Guard_Report.txt",
        mimetype="text/plain"
    )


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)