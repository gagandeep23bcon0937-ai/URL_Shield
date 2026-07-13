"""
URL Shield - Flask + Python phishing URL analyzer
Run with: python app.py
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request
from phishing_detector import analyze_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    entered_url = ""

    if request.method == "POST":
        entered_url = request.form.get("url", "")
        result = analyze_url(entered_url)

    return render_template("index.html", result=result, entered_url=entered_url)


@app.route("/analyze", methods=["GET"])
def analyze_api():
    url = request.args.get("url", "")
    return jsonify(analyze_url(url))


if __name__ == "__main__":
    app.run(debug=True)
