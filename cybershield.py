from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)


def analyze_url(url):
    url = url.strip()

    if not url or len(url) > 2048:
        return {
            "error": "Please enter a valid URL."
        }

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)

        if parsed.scheme not in ("http", "https"):
            raise ValueError

        if not parsed.hostname:
            raise ValueError

        host = parsed.hostname.encode("idna").decode("ascii")

        if any(ord(char) < 33 for char in url):
            raise ValueError

    except (ValueError, UnicodeError):
        return {
            "error": "Invalid URL format."
        }

    findings = []

    if parsed.scheme != "https":
        findings.append("The URL does not use HTTPS.")

    suspicious_words = [
        "login", "verify", "secure", "account", "update"
    ]

    searchable_url = url.lower()

    if any(word in searchable_url for word in suspicious_words):
        findings.append("The URL contains potentially suspicious keywords.")

    try:
        ipaddress.ip_address(host)
        findings.append("The hostname is an IP address.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("The hostname contains an internationalized domain label.")

    if "@" in parsed.netloc:
        findings.append("The URL contains user-info syntax that may be misleading.")

    if len(url) > 100:
        findings.append("The URL is unusually long.")

    return {
        "url": url,
        "findings": findings,
        "risk": "Review recommended" if findings else "No configured indicators detected",
        "count": len(findings)
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "")
        result = analyze_url(url)

    return render_template("scanner.html", result=result)


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/guide")
def guide():
    return render_template("guide.html")


if __name__ == "__main__":
    app.run(debug=True)
