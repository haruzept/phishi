from flask import Flask, request, render_template, redirect, flash
from email.parser import BytesParser
from email import policy
from email.utils import parseaddr
import re
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dein_geheimer_schluessel"

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

def check_from_field(msg, whitelist):
    sender = msg.get("From", "")
    display_name, email_addr = parseaddr(sender)
    email_domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    score = 0
    details = []
    if display_name and email_domain and display_name.lower() not in email_domain:
        if email_domain not in whitelist["domain"]:
            score += 30
            details.append(f"Anzeigename '{display_name}' passt nicht zur Domain '{email_domain}'.")
    return score, details, display_name.lower(), email_domain

def check_reply_to(msg, from_domain, display_name, whitelist):
    reply_to = msg.get("Reply-To", "")
    _, reply_address = parseaddr(reply_to)
    reply_domain = reply_address.split("@")[-1].lower() if "@" in reply_address else ""
    score = 0
    details = []
    if reply_domain and reply_domain not in from_domain and display_name not in reply_domain:
        if reply_domain not in whitelist["domain"] and reply_domain not in whitelist["mailserver"]:
            score += 25
            details.append("Antwortadresse passt nicht zum Absender oder widerspricht dem Absendernamen.")
    return score, details

def check_known_phishing_domains(urls):
    if not os.path.exists(DB_PATH):
        return 0, []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        score = 0
        details = []
        for url in urls:
            domain_match = re.search(r"https?://([^/]+)", url)
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

def check_links_against_whitelist(urls, whitelist):
    details = []
    clean_urls = []
    for url in urls:
        if any(part in url for part in whitelist["urlpart"]):
            details.append(f"Link {url} erkannt als whitelisted Tracking-Domain.")
        else:
            clean_urls.append(url)
    return clean_urls, details

def calculate_phishing_score(msg):
    whitelist = get_whitelist()
    overall_score = 0
    score_details = []

    score_from, details_from, display_name, from_domain = check_from_field(msg, whitelist)
    overall_score += score_from
    score_details.extend(details_from)

    score_reply, details_reply = check_reply_to(msg, from_domain, display_name, whitelist)
    overall_score += score_reply
    score_details.extend(details_reply)

    auth_results = msg.get("Authentication-Results", "").lower()
    if "spf=pass" in auth_results:
        overall_score -= 10
        score_details.append("SPF erfolgreich bestanden (positives Signal).")
    if "dkim=pass" in auth_results:
        overall_score -= 10
        score_details.append("DKIM erfolgreich bestanden (positives Signal).")
    if "dmarc=pass" in auth_results:
        overall_score -= 10
        score_details.append("DMARC erfolgreich bestanden (positives Signal).")

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

    urls = extract_urls(body)
    urls, whitelisted_url_hints = check_links_against_whitelist(urls, whitelist)
    score_details.extend(whitelisted_url_hints)

    score_links, details_links = check_known_phishing_domains(urls)
    overall_score += score_links
    score_details.extend(details_links)

    if overall_score < 0:
        overall_score = 0
    elif overall_score > 100:
        overall_score = 100

    return overall_score, list(set(score_details))

def analyze_email(msg):
    results = {
        "Subject": msg.get("Subject", "Kein Subject"),
        "From": msg.get("From", "Unbekannt"),
        "To": msg.get("To", "Unbekannt"),
        "Date": msg.get("Date", "Unbekannt"),
        "Reply-To": msg.get("Reply-To", "Nicht vorhanden"),
        "Received": "\n".join(msg.get_all("Received", [])[:3]) if msg.get_all("Received") else "Keine Received-Header vorhanden.",
    }

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

    results["URLs"] = extract_urls(body)
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
