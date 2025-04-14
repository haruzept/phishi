from flask import Flask, request, render_template, redirect, flash
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dein_geheimer_schluessel"

DB_PATH = "phishing_data.db"

def extract_urls(text):
    url_regex = re.compile(r'https?://[^\s"<>]+')
    return url_regex.findall(text)

def check_known_phishing_domains(urls):
    if not os.path.exists(DB_PATH):
        return 0, []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        score = 0
        details = []
        for url in urls:
            domain_match = re.search(r"https?://([\w\.-]+)/?", url)
            if domain_match:
                domain = domain_match.group(1).lower()
                cursor.execute("SELECT domain FROM phishing_domains WHERE domain = ?", (domain,))
                if cursor.fetchone():
                    score += 50
                    details.append(f"Domain {domain} ist in der bekannten Phishing-Datenbank.")
        return score, details
    except Exception as e:
        return 0, [f"Datenbankfehler bei Phishing-Check: {e}"]
    finally:
        conn.close()

def check_from_field(msg):
    sender = msg.get("From", "")
    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].strip(' "')
        email_addr = sender[sender.find("<")+1:sender.find(">")].strip()
    else:
        display_name, email_addr = parseaddr(sender)
    email_domain = email_addr.split('@')[-1].lower() if "@" in email_addr else ""
    details = []
    score = 0
    if display_name and email_domain and display_name.lower() not in email_domain:
        score += 40
        details.append(f"Anzeigename '{display_name}' passt nicht zur Domain '{email_domain}'.")
    return score, details

def check_report_mailto(body):
    score = 0
    details = []
    mailto_matches = re.findall(r'mailto:([^"?\s]+)', body)
    for mail in mailto_matches:
        _, address = parseaddr(mail)
        domain = address.split('@')[-1].lower() if "@" in address else ""
        if domain:
            if os.path.exists(DB_PATH):
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT domain FROM phishing_domains WHERE domain = ?", (domain,))
                    if cursor.fetchone():
                        score += 30
                        details.append(f"Mailto-Domain {domain} ist in der Phishing-Datenbank.")
                except Exception as e:
                    details.append(f"Datenbankfehler bei Mailto-Prüfung: {e}")
                finally:
                    conn.close()
    return score, details

def calculate_phishing_score(msg):
    overall_score = 0
    score_details = []

    score_from, details_from = check_from_field(msg)
    overall_score += score_from
    score_details.extend(details_from)

    auth_results = msg.get("Authentication-Results", "").lower()
    if "spf=temperror" in auth_results or "spf=none" in auth_results:
        overall_score += 10
        score_details.append("SPF-Ergebnis weist auf Fehler hin.")
    if "dkim=none" in auth_results:
        overall_score += 10
        score_details.append("DKIM fehlt.")

    received_headers = msg.get_all("Received", [])
    for header in received_headers:
        if "(::1)" in header:
            overall_score += 5
            score_details.append("Received-Header enthält loopback (::1).")
            break

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    body += part.get_content()
                except Exception:
                    continue
    else:
        body = msg.get_content()

    report_score, report_details = check_report_mailto(body)
    overall_score += report_score
    score_details.extend(report_details)

    urls = extract_urls(body)
    phishing_db_score, phishing_db_details = check_known_phishing_domains(urls)
    overall_score += phishing_db_score
    score_details.extend(phishing_db_details)

    if overall_score > 100:
        overall_score = 100
    return overall_score, score_details

def analyze_email(msg):
    results = {}
    results["Subject"] = msg.get("Subject", "Kein Subject")
    results["From"] = msg.get("From", "Unbekannt")
    results["To"] = msg.get("To", "Unbekannt")
    results["Date"] = msg.get("Date", "Unbekannt")
    reply_to = msg.get("Reply-To", "")
    results["Reply-To"] = reply_to if reply_to else "Nicht vorhanden"

    received_headers = msg.get_all("Received", [])
    results["Received"] = "\n".join(received_headers[:3]) if received_headers else "Keine Received-Header vorhanden."

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

    phishing_score, score_details = calculate_phishing_score(msg)
    results["phishing_probability"] = phishing_score
    results["score_details"] = score_details
    results["Warnung"] = score_details[0] if score_details else "Keine Auffälligkeiten erkannt."

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
