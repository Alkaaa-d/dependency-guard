from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from parser import parse_requirements
from risk_engine import calculate_risk
import os

# OPTIONAL graph support
try:
    from graph_generator import generate_dependency_graph
    GRAPH_ENABLED = True
except Exception:
    GRAPH_ENABLED = False

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ✅ Check allowed file type
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ✅ Executive Summary Generator
def generate_executive_summary(results):
    high = sum(1 for r in results if r["risk"] == "High")
    medium = sum(1 for r in results if r["risk"] == "Medium")
    low = sum(1 for r in results if r["risk"] == "Low")

    if not results:
        return "No dependencies analyzed yet."

    return (
        f"This project contains {high} high-risk, "
        f"{medium} medium-risk, and {low} low-risk dependencies. "
        "Immediate action is recommended for high-risk components."
    )


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    summary = {"low": 0, "medium": 0, "high": 0}

    if request.method == "POST":
        file = request.files.get("file")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            dependencies = parse_requirements(filepath)
            results = calculate_risk(dependencies)

            # Generate dependency graph
            if GRAPH_ENABLED and results:
                try:
                    generate_dependency_graph(results)
                except Exception as e:
                    print("Graph generation failed:", e)

            summary = {
                "low": sum(1 for r in results if r["risk"] == "Low"),
                "medium": sum(1 for r in results if r["risk"] == "Medium"),
                "high": sum(1 for r in results if r["risk"] == "High"),
            }

    # ✅ Overall Risk Score
    overall_score = (
        sum(r["score"] for r in results) / len(results)
        if results else 0
    )

    # ✅ Executive Summary
    executive_summary = generate_executive_summary(results)

    return render_template(
        "index.html",
        results=results,
        summary=summary,
        overall_score=round(overall_score, 2),
        executive_summary=executive_summary
    )


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)
