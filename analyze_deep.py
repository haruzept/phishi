import os
import logging
from flask import Flask, render_template, request, flash
from werkzeug.utils import secure_filename
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import sqlite3

from check_dns import check_dns
from check_whois import check_domain_age
from score_weights import get_color_for_score, DKIM_FAIL, SPF_FAIL, DMARC_FAIL, DISPLAY_NAME_MISMATCH
from check_links import check_links  # benutze die aktuelle Version ohne Companion-Domains

# Konfiguriere Logging (ohne sensible Daten)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "phishi"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def extract_domain(email_address):
    parts = email_address.split('@')
    return parts[1].lower() if len(parts) == 2 else ""

def extract_urls(msg):
    urls = []
    url_regex = re.compile(r'https?://[^\s"\'<>]+')
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        urls.extend(url_regex.findall(text))
                except Exception as e:
                    logging.error("Error decoding part: %s", e)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            text = payload.decode(charset, errors='replace')
            urls.extend(url_regex.findall(text))
    return list(set(urls))

def get_headers_str(msg):
    """
    Gibt alle Header des E-Mail-Objekts als Text-String zurück (Name: Wert).
    """
    headers_str = ""
    for name, value in msg.items():
        headers_str += f"{name}: {value}\n"
    return headers_str

def is_domain_known_phishing(domain):
    """
    Prüft, ob die angegebene Basisdomain in der Phishing-Datenbank vorhanden ist.
    """
    try:
        conn = sqlite3.connect("phishing_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM phishing_domains WHERE domain = ? LIMIT 1", (domain,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        logging.error("Fehler beim Zugriff auf die Phishing-Datenbank: %s", e)
        return False

def get_enduser_explanation(score):
    """
    Erzeugt eine einfache Erklärung (Liste von Sätzen) für den Endanwender,
    abhängig vom ermittelten Score.
    """
    if score == 0:
        return [
            "Die Analyse ergab keinerlei Auffälligkeiten.",
            "Diese E-Mail scheint sehr wahrscheinlich echt zu sein."
        ]
    elif score < 25:
        return [
            "Es wurden nur wenige (möglicherweise harmlose) Auffälligkeiten gefunden.",
            "Die E-Mail wirkt wahrscheinlich echt, dennoch sollte man vorsichtig bleiben."
        ]
    elif score < 60:
        return [
            "Einige Indizien deuten auf mögliche Manipulation hin.",
            "Wir empfehlen, die E-Mail genauer zu prüfen."
        ]
    else:
        return [
            "Mehrere Merkmale deuten stark auf Phishing hin.",
            "Seien Sie besonders vorsichtig und klicken Sie keine Links an."
        ]

def analyze_email(msg):
    technical_results = []
    total_score = 0

    # Header-Infos
    raw_headers = get_headers_str(msg)
    auth_results_header = msg.get('Authentication-Results', '')
    dkim_signature_header = msg.get('DKIM-Signature', '')
    received_spf_header = msg.get('Received-SPF', '')

    from_header = msg.get('From', "")
    display_name, email_address = parseaddr(from_header)
    from_domain = extract_domain(email_address)
    base_domain = get_base_domain(from_domain)

    # DNS- und WHOIS-Prüfungen anhand der Basisdomain
    for check_func in [check_dns, check_domain_age]:
        score, details = check_func(base_domain)
        technical_results.extend(details)
        total_score += score

    # Authentifizierungs-Ergebnisse auswerten
    auth_results = auth_results_header.lower()
    if auth_results:
        if 'spf=fail' in auth_results or 'spf=temperror' in auth_results:
            total_score += SPF_FAIL
            technical_results.append("SPF-Prüfung fehlgeschlagen (laut Authentication-Results).")
        if 'dkim=fail' in auth_results or 'dkim=none' in auth_results:
            total_score += DKIM_FAIL
            technical_results.append("DKIM-Prüfung fehlgeschlagen (laut Authentication-Results).")
        if 'dmarc=fail' in auth_results or 'dmarc=none' in auth_results:
            total_score += DMARC_FAIL
            technical_results.append("DMARC-Prüfung fehlgeschlagen (laut Authentication-Results).")

    # Anzeigename-Mismatch: Prüfe, ob das Kernstichwort der Basisdomain im Anzeigenamen vorhanden ist.
    brand = base_domain.split('.')[0]
    if display_name and brand not in display_name.lower():
        total_score += DISPLAY_NAME_MISMATCH
        technical_results.append(f"Anzeigename passt nicht zur Domain: {display_name} ≠ {base_domain}")

    # Zusätzliche Prüfung: Brand-Impersonation
    popular_brands = ["paypal", "amazon", "google", "apple", "microsoft"]
    for br in popular_brands:
        if br in display_name.lower() and br not in from_domain.lower():
            total_score += 15  # zusätzlicher Score für offensichtliche Marken-Mismatch
            technical_results.append(f"Anzeigename enthält bekannte Marke '{br}', passt aber nicht zur tatsächlichen Domain.")

    # URLs aus dem E-Mail-Inhalt extrahieren und prüfen
    urls = extract_urls(msg)
    if urls:
        score, details = check_links(urls, expected_domain=base_domain)
        total_score += score
        technical_results.extend(details)
    else:
        technical_results.append("Keine URLs im E-Mail-Inhalt gefunden.")

    # Datenbank-Prüfung: Wird die Basisdomain als Phishing-Domain erkannt, wird der Score auf 100 gesetzt.
    if is_domain_known_phishing(base_domain):
        technical_results.append(f"Domain {base_domain} ist in der Phishing-Datenbank vorhanden.")
        final_score = 100
    else:
        final_score = min(total_score, 100)  # Score maximal 100

    color, color_hint = get_color_for_score(final_score)
    why_message = get_enduser_explanation(final_score)

    logging.info("Analyse abgeschlossen: Score=%d, Domain=%s", final_score, base_domain)

    return {
        "phishing_probability": final_score,
        "phishing_color": color,
        "phishing_hint": color_hint,
        "score_details": technical_results,
        "why_message": why_message,
        "raw_headers": raw_headers,
        "authentication_results_header": auth_results_header,
        "dkim_signature_header": dkim_signature_header,
        "received_spf_header": received_spf_header,
        "From": from_header,
        "Subject": msg.get("Subject", ""),
        "To": msg.get("To", ""),
        "Date": msg.get("Date", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "URLs": urls
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'email_file' not in request.files:
            flash("Keine Datei hochgeladen.")
            return render_template('index.html')

        file = request.files['email_file']
        if file.filename == '':
            flash("Keine Datei ausgewählt.")
            return render_template('index.html')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            with open(filepath, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)

            analysis_result = analyze_email(msg)

            # DSGVO-Konform: Lösche die hochgeladene Datei nach der Analyse sofort
            try:
                os.remove(filepath)
            except Exception as e:
                logging.error("Fehler beim Löschen der Datei: %s", e)

            return render_template('result.html', analysis=analysis_result)

        flash("Ungültiger Dateityp. Bitte eine .eml-Datei hochladen.")
        return render_template('index.html')

    return render_template('index.html')

if __name__ == '__main__':
    app.run()
