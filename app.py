from flask import Flask, request, render_template, redirect, flash
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re

app = Flask(__name__)
app.secret_key = "dein_geheimer_schluessel"  # Bitte einen sicheren Wert wählen

def extract_urls(text):
    # Suche nach http- und https-URLs ohne unerwünschte Zeichen
    url_regex = re.compile(r'https?://[^\s"<>]+')
    return url_regex.findall(text)

def check_from_field(msg):
    sender = msg.get("From", "")
    # Wenn der Sender ein "<" enthält, extrahieren wir manuell den Teil davor als Anzeigename
    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].strip(" \"")
        email_addr = sender[sender.find("<")+1:sender.find(">")].strip()
    else:
        # Fallback: nutze parseaddr
        display_name, email_addr = parseaddr(sender)
    email_domain = email_addr.split('@')[-1].lower() if "@" in email_addr else ""
    details = []
    score = 0
    # Prüfe anhand eines Regex im Anzeigenamen, ob "microsoft account" vorkommt
    if display_name and re.search(r'microsoft\s+account', display_name, re.IGNORECASE):
        if "microsoft.com" not in email_domain:
            score = 100
            details.append(f"Anzeigename '{display_name}' suggeriert offiziellen Absender, aber die Adresse ist {email_addr}.")
        else:
            details.append("Anzeigename und Absenderadresse stimmen überein.")
    return score, details

def check_report_mailto(body):
    """
    Sucht im HTML-Body nach mailto:-Links und prüft, ob diese verdächtige Domains (z. B. gmail.com)
    enthalten.
    """
    score = 0
    details = []
    mailto_matches = re.findall(r'mailto:([^"?\s]+)', body)
    for mail in mailto_matches:
        _, address = parseaddr(mail)
        domain = address.split('@')[-1].lower() if "@" in address else ""
        if domain == "gmail.com":
            score += 20
            details.append(f"Report-Link verweist auf {address} (gmail.com) statt auf eine offizielle Adresse.")
    return score, details

def calculate_phishing_score(msg):
    overall_score = 0
    score_details = []

    # Heuristik 1: From-Header prüfen (Anzeigename vs. Adresse)
    score_from, details_from = check_from_field(msg)
    overall_score += score_from
    score_details.extend(details_from)

    # Heuristik 2: Authentifizierungs-Ergebnisse (SPF, DKIM)
    auth_results = msg.get("Authentication-Results", "").lower()
    if "spf=temperror" in auth_results or "spf=none" in auth_results:
        overall_score += 10
        score_details.append("SPF-Ergebnis weist auf Fehler hin.")
    if "dkim=none" in auth_results:
        overall_score += 10
        score_details.append("DKIM fehlt.")

    # Heuristik 3: Received-Header prüfen (z. B. Loopback (::1))
    received_headers = msg.get_all("Received", [])
    for header in received_headers:
        if "(::1)" in header:
            overall_score += 5
            score_details.append("Received-Header enthält loopback (::1).")
            break

    # Heuristik 4: HTML-Body analysieren und mailto-Links prüfen
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

    # Heuristik 5: URLs im Body überprüfen (Beispiel: d3l.com statt dhl.com)
    urls = extract_urls(body)
    for url in urls:
        m = re.search(r"https?://([\w\.-]+)/?", url)
        if m:
            url_domain = m.group(1).lower()
            # Beispielregel: Falls der Link auf "d3l.com" verweist (statt erwarteter Domain)
            if "d3l.com" in url_domain:
                overall_score = 100
                score_details.append("Link verweist auf d3l.com statt auf die erwartete Domain.")
                break

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

    # Ersten 3 Received-Header sammeln
    received_headers = msg.get_all("Received", [])
    results["Received"] = "\n".join(received_headers[:3]) if received_headers else "Keine Received-Header vorhanden."

    # Body aus Text- und HTML-Teilen extrahieren und URLs suchen
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

    # Phishing-Score und Detailinformationen berechnen
    phishing_score, score_details = calculate_phishing_score(msg)
    results["phishing_probability"] = phishing_score
    results["score_details"] = score_details

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
