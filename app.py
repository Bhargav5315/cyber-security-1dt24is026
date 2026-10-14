from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)


def analyze_url(raw_url):
    """Analyze a URL using basic phishing warning rules."""

    raw_url = (raw_url or "").strip()

    if not raw_url or len(raw_url) > 2048:
        return {
            "status": "Invalid URL",
            "score": 0,
            "findings": ["Enter a URL between 1 and 2048 characters."],
            "url": None
        }

    if any(ch.isspace() or ord(ch) < 32 for ch in raw_url):
        return {
            "status": "Invalid URL",
            "score": 0,
            "findings": ["The URL must not contain spaces or control characters."],
            "url": None
        }

    # Add HTTPS when the user enters a domain without a scheme.
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Unsupported URL scheme.")

        host = parsed.hostname

        if not host or not parsed.netloc:
            raise ValueError("Missing hostname.")

        # Accessing port validates malformed port numbers.
        _ = parsed.port

        host = host.lower().rstrip(".")

        # Validate IP addresses and ordinary domain names.
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            if host == "localhost":
                pass
            elif len(host) > 253 or "." not in host:
                raise ValueError("Invalid hostname.")
            elif any(not label or len(label) > 63
                     for label in host.split(".")):
                raise ValueError("Invalid hostname.")
            elif any(
                not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
                for label in host.split(".")
            ):
                raise ValueError("Invalid hostname.")

        findings = []
        score = 0

        if parsed.scheme.lower() != "https":
            findings.append(
                "HTTP is used instead of HTTPS; the connection may not be encrypted."
            )
            score += 10

        if "@" in parsed.netloc:
            findings.append(
                "The URL contains @, which can make the actual destination confusing."
            )
            score += 25

        if len(raw_url) > 100:
            findings.append("The URL is unusually long.")
            score += 10

        if is_ip:
            findings.append(
                "The website uses an IP address instead of a domain name."
            )
            score += 20

        if "xn--" in host:
            findings.append(
                "The domain uses internationalized hostname encoding."
            )
            score += 20

        if host.count("-") >= 3:
            findings.append("The hostname contains several hyphens.")
            score += 10

        suspicious_terms = (
            "verify", "password", "account", "signin",
            "secure", "wallet", "banking", "login"
        )

        if any(term in raw_url.lower() for term in suspicious_terms):
            findings.append(
                "The URL contains words sometimes used in phishing links."
            )
            score += 10

        score = min(score, 100)

        if score >= 40:
            status = "Suspicious"
        elif score >= 15:
            status = "Needs Review"
        else:
            status = "No Basic Warning Signs"

        if not findings:
            findings.append(
                "No warning signs were detected by the basic checks."
            )

        findings.append(
            "This is a rule-based estimate, not a verified security verdict."
        )

        return {
            "status": status,
            "score": score,
            "findings": findings,
            "url": raw_url
        }

    except (ValueError, UnicodeError):
        return {
            "status": "Invalid URL",
            "score": 0,
            "findings": [
                "Enter a valid HTTP or HTTPS website URL and check its format."
            ],
            "url": None
        }


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    entered_url = ""

    if request.method == "POST":
        entered_url = request.form.get("url", "")
        result = analyze_url(entered_url)

    return render_template(
        "index.html",
        result=result,
        entered_url=entered_url
    )


if __name__ == "__main__":
    app.run(debug=True)
