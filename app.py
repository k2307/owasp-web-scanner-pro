from flask import Flask, render_template, request, send_file
import asyncio
import uuid
import os
from scanner.engine import ScannerEngine
from scanner.reporter import generate_pdf

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")

        if not target.startswith("http"):
            return render_template("index.html", error="Target must start with http or https")

        engine = ScannerEngine(target)
        issues = asyncio.run(engine.run_all())

        report_name = f"reports/report_{uuid.uuid4()}.pdf"
        generate_pdf(issues, report_name)

        high = len([i for i in issues if i['severity']=="High"])
        medium = len([i for i in issues if i['severity']=="Medium"])
        low = len([i for i in issues if i['severity']=="Low"])

        return render_template("results.html",
                               issues=issues,
                               report=report_name,
                               high=high,
                               medium=medium,
                               low=low)

    return render_template("index.html")

@app.route("/download/<path:filename>")
def download(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
