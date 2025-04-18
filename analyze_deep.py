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
from score_weights import (
    get_color_for_score,
    DKIM_FAIL,
    SPF_FAIL,
    DMARC_FAIL,
    DISPLAY_NAME_MISMATCH,
    FREEMAIL_REPLY_TO
)
from check_links import check_links  # benutze die aktuelle Version ohne Companion-Domains

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "phishi"
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def extract_domain(email_address):
    parts = email_address.split('@')
    return parts[1].lower() if len(parts) == 2 else ""

def extract_body_text(msg):
    """Sammelt den gesamten Text aus text/plain- und text/html-Teilen."""
    texts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        texts.append(payload.decode(part.get_content_charset('utf-8'),
                                                    errors='replace'))
                except Exception as e:
                    logging.error("Error decoding part: %s", e)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            texts.append(payload.decode(msg.get_content_charset('utf-8'),
                                        errors='replace'))
    return "\n".join(texts)

def is_domain_known_phishing(domain):
    try:
        conn = sqlite3.connect("phishing_data.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM phishing_domains WHERE domain = ? LIMIT 1",
            (domain,)
        )
        found = cursor.fetchone() is not None
        conn.close()
        return found
    except Exception as e:
        logging.error("Fehler beim Zugriff auf Phishing-DB: %s", e)
        return False

def analyze_email(msg):
    total_score = 0
    user_reasons = []

    # Absender
    from_header = msg.get('From', "")
    display_name, email_address = parseaddr(from_header)
    from_domain = extract_domain(email_address)
    base_domain = get_base_domain(from_domain)

    # Reply‑To
    reply_to = msg.get('Reply-To', "")
    reply_to_domain = extract_domain(parseaddr(reply_to)[1])
    if reply_to and reply_to_domain != base_domain:
        total_score += FREEMAIL_REPLY_TO
        user_reasons.append("Reply-To weicht von der Absenderdomain ab.")

    # DNS & WHOIS
    dns_score, dns_details = check_dns(base_domain)
    whois_score, whois_details = check_domain_age(base_domain)
    total_score += dns_score + whois_score

    # Authentifizierungs-Header
    auth = msg.get('Authentication-Results', '').lower()
    if 'spf=fail' in auth or 'spf=temperror' in auth:
        total_score += SPF_FAIL
        user_reasons.append("SPF-Prüfung fehlgeschlagen.")
    if 'dkim=fail' in auth or 'dkim=none' in auth:
        total_score += DKIM_FAIL
        user_reasons.append("DKIM-Prüfung fehlgeschlagen.")
    if 'dmarc=fail' in auth or 'dmarc=none' in auth:
        total_score += DMARC_FAIL
        user_reasons.append("DMARC-Prüfung fehlgeschlagen.")

    # Anzeigename‑Mismatch
    brand = base_domain.split('.')[0]
    if display_name and brand not in display_name.lower():
        total_score += DISPLAY_NAME_MISMATCH
        user_reasons.append("Absenderadresse passt nicht zur Absenderdomain.")

    # Dringlichkeit erkennen
    body = extract_body_text(msg)
    if re.search(r'\bjetzt\s+sofort\b', body, flags=re.IGNORECASE) or \
       re.search(r'\bkennwort\s+ändern\b', body, flags=re.IGNORECASE):
        total_score += 10
        user_reasons.append("Dringender Handlungsaufruf im Text erkannt.")

    # Phishing-Datenbank
    if is_domain_known_phishing(base_domain):
        total_score = 100
        user_reasons = ["Bekannte Phishing-Domain."]
    
    # Final Score
    final_score = min(total_score, 100)
    color, hint = get_color_for_score(final_score)

    return {
        "phishing_probability": final_score,
        "phishing_color": color,
        # nur user‑friendly Gründe
        "why_message": user_reasons or ["Keine auffälligen Merkmale entdeckt."],
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
        if not allowed_file(file.filename):
            flash("Ungültiger Dateityp. Bitte .eml-Datei hochladen.")
            return render_template('index.html')

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        path = os.path.join(app.config['UPLOAD_FOLDER'],
                            secure_filename(file.filename))
        file.save(path)
        with open(path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        os.remove(path)

        analysis = analyze_email(msg)
        return render_template('result.html', analysis=analysis)

    return render_template('index.html')

if __name__ == '__main__':
    app.run()
