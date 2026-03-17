from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from parser import parse_requirements
from risk_engine import calculate_risk
from url_scanner import scan_general_url

import os
import requests
import re

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "json", "xml"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# API key for phone verification
PHONE_API_KEY = "EOsVa5hVeqProDWGEMtTI2IOjrr5G0BB"


# ------------------------------------
# Utility
# ------------------------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------------------
# EMAIL BREACH CHECK (XposedOrNot)
# ------------------------------------

def check_email_breach(email):

    url = f"https://api.xposedornot.com/v1/check-email/{email}"

    try:
        response = requests.get(url, timeout=6)

        if response.status_code != 200:
            return []

        data = response.json()

        if data.get("breaches"):
            return data["breaches"]

        return []

    except Exception:
        return []


# ------------------------------------
# MESSAGE SCAN
# ------------------------------------

def scan_message(message):

    original_input = message
    processed_input = message.strip()

    risk = "Low"
    score = 10
    reasons = []

    suspicious_keywords = [
        "urgent", "verify", "otp", "bank",
        "lottery", "winner", "click here",
        "account suspended", "free", "claim now"
    ]

    detected = [word for word in suspicious_keywords if word in processed_input.lower()]

    if detected:
        risk = "High"
        score = 70
        reasons.append(f"Suspicious keywords detected: {', '.join(detected)}")

    if "http://" in processed_input or "https://" in processed_input:
        score += 15
        reasons.append("Message contains external link")

    if not reasons:
        reasons.append("No phishing indicators detected")

    return {
        "original_input": original_input,
        "processed_input": processed_input,
        "risk": risk,
        "score": min(score, 100),
        "details": reasons,
        "recommendation": "Do not share OTP or click unknown links."
    }


# ------------------------------------
# PHONE SCAN
# ------------------------------------

def scan_phone_number(number):

    original_input = number
    processed_number = number.strip()

    processed_number = re.sub(r"[^\d+]", "", processed_number)

    if processed_number.count("+") > 1:
        processed_number = processed_number.replace("+", "")

    if not re.fullmatch(r"\+?\d{10,15}", processed_number):
        return {
            "original_input": original_input,
            "processed_input": processed_number,
            "risk": "High",
            "score": 90,
            "details": ["Invalid phone number format"],
            "recommendation": "Please enter a valid phone number."
        }

    try:

        url = f"https://api.apilayer.com/number_verification/validate?number={processed_number}"

        headers = {"apikey": PHONE_API_KEY}

        response = requests.get(url, headers=headers, timeout=6)

        if response.status_code != 200:
            raise Exception("API error")

        data = response.json()

    except Exception:

        return {
            "original_input": original_input,
            "processed_input": processed_number,
            "risk": "Medium",
            "score": 50,
            "details": ["Phone verification API failed"],
            "recommendation": "Unable to verify phone number"
        }

    valid = data.get("valid", False)

    risk = "Low"
    score = 15
    details = []

    if not valid:
        risk = "High"
        score = 85
        details.append("Phone number not valid")
    else:
        details.append("Phone verified successfully")

    if processed_number.endswith(("0000", "1234")):
        risk = "Medium"
        score = 60
        details.append("Suspicious repeated digits")

    return {
        "original_input": original_input,
        "processed_input": processed_number,
        "risk": risk,
        "score": score,
        "details": details,
        "recommendation": "Avoid sharing sensitive information"
    }


# ------------------------------------
# DASHBOARD
# ------------------------------------

@app.route("/", methods=["GET", "POST"])
def index():

    results = []
    summary = {"low": 0, "medium": 0, "high": 0}
    file_content = None

    if request.method == "POST":

        file = request.files.get("file")
        url_input = request.form.get("url")
        hash_value = request.form.get("hash")

        if file and allowed_file(file.filename):

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            file.save(filepath)

            with open(filepath, "r", encoding="utf-8") as f:
                file_content = f.read()

            dependencies = parse_requirements(filepath)

            if dependencies:
                results = calculate_risk(dependencies)

        elif url_input and url_input.startswith(("http://", "https://")):

            url_result = scan_general_url(url_input)

            results = [{
                "original_input": url_input,
                "risk": url_result.get("risk", "Low"),
                "score": url_result.get("score", 10),
                "details": url_result.get("details", []),
                "recommendation": "Verify HTTPS and inspect suspicious keywords"
            }]

        elif hash_value:

            results = [{
                "original_input": hash_value,
                "risk": "Low",
                "score": 10,
                "details": ["Basic hash pattern analysis"],
                "recommendation": "Investigate hash origin if suspicious"
            }]

        summary = {
            "low": sum(1 for r in results if r.get("risk") == "Low"),
            "medium": sum(1 for r in results if r.get("risk") == "Medium"),
            "high": sum(1 for r in results if r.get("risk") == "High"),
        }

    return render_template("index.html", results=results, summary=summary, file_content=file_content)


# ------------------------------------
# PHISHING PAGE
# ------------------------------------

@app.route("/phishing", methods=["GET", "POST"])
def phishing():

    result = None
    scan_type = None

    if request.method == "POST":

        message_input = request.form.get("message")
        phone_input = request.form.get("phone")

        if message_input:
            scan_type = "message"
            result = scan_message(message_input)

        elif phone_input:
            scan_type = "phone"
            result = scan_phone_number(phone_input)

    return render_template("phishing.html", result=result, scan_type=scan_type)


# ------------------------------------
# BREACH CHECKER PAGE (EMAIL)
# ------------------------------------

@app.route("/breach", methods=["GET", "POST"])
def breach():

    result = None
    email = None

    if request.method == "POST":

        email = request.form.get("email")

        if email:

            breaches = check_email_breach(email)

            if breaches:
                result = breaches
            else:
                result = "No breach found"

    return render_template("breach.html", result=result, email=email)


# ------------------------------------

if __name__ == "__main__":

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    app.run(debug=True)