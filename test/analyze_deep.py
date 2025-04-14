
from flask import Flask, request, render_template, redirect, flash
from email.parser import BytesParser
from email import policy
from email.utils import parseaddr
import re
import sqlite3
import os

from check_dns import check_dns
from check_whois import check_domain_age
from check_links import check_links, check_freemailer_abuse
from score_weights import *

app = Flask(__name__)
app.secret_key = "supersecret"

DB_PATH = "phishing_data.db"

def extract_urls(text):
    url_regex = re.compile(r'https?://[\w\.-/\?=&%#]+')
    return url_regex.findall(text)

def get_whitelist():
    entries = {"domain": set(), "urlpart": set(), "mailserver": set()}
    if not os.path.exists(DB_PATH):
        return entries
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT type, value FROM whitelist")
        for t, v in cursor.fetchall():
            entries[t].add(v.lower())
    except Exception:
        pass
    finally:
        conn.close()
    return entries

def analyze_email(msg):
    results = {}
    whitelist = get_whitelist()
    overall_score = 0
    score_details = []

    # Grundlegende Headerdaten
    results["Subject"] = msg.get("Subject", "Kein Betreff")
    results["From"] = msg.get("From", "Unbekannt")
    results["To"] = msg.get("To", "Unbekannt")
    results["Date"] = msg.get("Date", "Unbekannt")
    results["Reply-To"] = msg.get("Reply-To", "Nicht vorhanden")
    received = msg.get_all("Received", [])
    results["Received"] = "\n".join(received[:3]) if received else "Keine Header vorhanden."

    # Absenderauswertung
    display_name, from_addr = parseaddr(msg.get("From", ""))
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    score, details = check_dns(from_domain)
    overall_score += score
    score_details.extend(details)

    score, details = check_domain_age(from_domain)
    overall_score += score
    score_details.extend(details)

    score, details = check_freemailer_abuse(from_domain, display_name)
    overall_score += score
    score_details.extend(details)

    # Authentifizierungsprüfung
    auth_results = msg.get("Authentication-Results", "").lower()
    if "spf=pass" in auth_results:
        overall_score += SPF_PASS
        score_details.append("SPF bestanden.")
    elif "spf=fail" in auth_results or "spf=none" in auth_results:
        overall_score += SPF_FAIL
        score_details.append("SPF-Fehler erkannt.")

    if "dkim=pass" in auth_results:
        overall_score += DKIM_PASS
        score_details.append("DKIM bestanden.")
    elif "dkim=fail" in auth_results or "dkim=none" in auth_results:
        overall_score += DKIM_FAIL
        score_details.append("DKIM-Fehler erkannt.")

    if "dmarc=pass" in auth_results:
        overall_score += DMARC_PASS
        score_details.append("DMARC bestanden.")
    elif "dmarc=fail" in auth_results or "dmarc=none" in auth_results:
        overall_score += DMARC_FAIL
        score_details.append("DMARC-Fehler erkannt.")

    if "spf=-all" in auth_results:
        overall_score += SPF_STRICT
        score_details.append("SPF enthält harten Reject (-all).")

    if "policy=reject" in auth_results:
        overall_score += DMARC_POLICY_REJECT
        score_details.append("DMARC Policy ist 'reject'.")

    # Reply-To Abweichung
    reply = msg.get("Reply-To", "")
    _, reply_addr = parseaddr(reply)
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    if reply_domain and reply_domain != from_domain:
        if reply_domain not in whitelist["domain"]:
            overall_score += REPLYTO_MISMATCH
            score_details.append("Antwortadresse passt nicht zum Absender.")

    # Anzeigename passt nicht zur Domain
    if display_name and from_domain and display_name.lower() not in from_domain:
        if from_domain not in whitelist["domain"]:
            overall_score += DISPLAYNAME_MISMATCH
            score_details.append(f"Anzeigename '{display_name}' passt nicht zur Domain '{from_domain}'.")

    # URLs analysieren
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body += part.get_content()
                except Exception:
                    continue
    else:
        body = msg.get_content()

    urls = extract_urls(body)
    results["URLs"] = urls

    score, details = check_links(urls)
    overall_score += score
    score_details.extend(details)

    if overall_score < 0:
        overall_score = 0
    if overall_score > 100:
        overall_score = 100

    results["phishing_probability"] = overall_score
    results["score_details"] = list(set(score_details))  # Duplikate raus
    return results

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if 'email_file' not in request.files:
            flash("Keine Datei ausgewählt.")
            return redirect(request.url)
        file = request.files["email_file"]
        if file.filename == "":
            flash("Keine Datei ausgewählt.")
            return redirect(request.url)
        try:
            msg = BytesParser(policy=policy.default).parse(file)
        except Exception as e:
            return f"Fehler beim Parsen der E-Mail: {e}"
        analysis_result = analyze_email(msg)
        return render_template("result.html", analysis=analysis_result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
