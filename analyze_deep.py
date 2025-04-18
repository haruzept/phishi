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
    FREEMAIL_REPLY_TO,
    URGENCY_PHRASE
)

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "phishi"

# Phrases indicating urgency/time pressure
URGENCY_KEYWORDS = [r"jetzt", r"sofort", r"dringend", r"umgehend", r"passwort ändern", r"kennwort ändern"]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_domain(email_address):
    parts = email_address.split('@')
    return parts[1].lower() if len(parts) == 2 else ""

def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def extract_text(msg):
    # Volltext aller text/plain und text/html Teile für Analyse
    texts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset('utf-8'), errors='replace')
                        texts.append(text)
                except Exception as e:
                    logging.error("Error decoding part: %s", e)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            texts.append(payload.decode(msg.get_content_charset('utf-8'), errors='replace'))
    return "
".join(texts)

def extract_urls(msg):
    urls = []
    url_regex = re.compile(r'https?://[^\s"\"\'<>]+')
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset('utf-8'), errors='replace')
                        urls.extend(url_regex.findall(text))
                except Exception as e:
                    logging.error("Error decoding part: %s", e)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode(msg.get_content_charset('utf-8'), errors='replace')
            urls.extend(url_regex.findall(text))
    return list(set(urls))

def get_headers_str(msg):
    headers = ""
    for name, value in msg.items():
        headers += f"{name}: {value}\n"
    return headers

def is_domain_known_phishing(domain):
    try:
        conn = sqlite3.connect("phishing_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM phishing_domains WHERE domain = ? LIMIT 1", (domain,))
        found = cursor.fetchone() is not None
        conn.close()
        return found
    except Exception as e:
        logging.error("Error accessing phishing database: %s", e)
        return False

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
            flash("Ungültiger Dateityp. Bitte eine .eml-Datei hochladen.")
            return render_template('index.html')

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)

        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        from_header = msg.get('From', '')
        _, email_address = parseaddr(from_header)
        from_domain = extract_domain(email_address)
        base_domain = get_base_domain(from_domain)

        total_score = 0
        technical_results = []

        dns_score, dns_details = check_dns(base_domain)
        whois_score, whois_details = check_domain_age(base_domain)
        total_score += dns_score + whois_score
        technical_results += dns_details + whois_details

        auth = msg.get('Authentication-Results', '').lower()
        if any(x in auth for x in ('spf=fail', 'spf=temperror', 'spf=none')):
            total_score += SPF_FAIL
            technical_results.append("SPF-Prüfung fehlgeschlagen oder nicht vorhanden.")
        if any(x in auth for x in ('dkim=fail', 'dkim=none')):
            total_score += DKIM_FAIL
            technical_results.append("DKIM-Signatur fehlt oder ungültig.")
        if any(x in auth for x in ('dmarc=fail', 'dmarc=none', 'dmarc=permerror')):
            total_score += DMARC_FAIL
            technical_results.append("DMARC-Prüfung fehlgeschlagen oder fehlerhaft.")

        display_name, _ = parseaddr(from_header)
        if display_name and display_name.lower().split()[0] not in base_domain.lower():
            total_score += DISPLAY_NAME_MISMATCH
            technical_results.append(f"Anzeigename passt nicht zur Domain: {display_name} ≠ {base_domain}.")

        popular_brands = ["paypal", "amazon", "google", "apple", "microsoft"]
        for br in popular_brands:
            if br in display_name.lower() and br not in base_domain.lower():
                total_score += DISPLAY_NAME_MISMATCH
                technical_results.append(f"Brand-Impersonation: {br} im Anzeigenamen, passt nicht zur Domain.")

        reply_to = msg.get('Reply-To', '')
        reply_domain = extract_domain(reply_to)
        if reply_domain and reply_domain != base_domain:
            total_score += FREEMAIL_REPLY_TO
            technical_results.append(f"Reply-To-Domain weicht ab: {reply_domain} != {base_domain}.")

        body_text = extract_text(msg).lower()
        if any(kw in body_text for kw in URGENCY_KEYWORDS):
            total_score += URGENCY_PHRASE
            technical_results.append("E-Mail erzeugt künstlichen Zeitdruck durch Schlüsselwörter.")

        urls = extract_urls(msg)
        if urls:
            link_score, link_details = check_links(urls, expected_domain=base_domain)
            total_score += link_score
            technical_results += link_details
        else:
            technical_results.append("Keine Links gefunden.")

        if is_domain_known_phishing(base_domain):
            total_score = 100
            technical_results.append("Domain ist als Phishing bekannt.")

        final_score = min(total_score, 100)
        color, _ = get_color_for_score(final_score)

        user_reasons = []
        if any('spf-prüfung' in d.lower() or 'dkim' in d.lower() or 'dmarc' in d.lower() for d in technical_results):
            user_reasons.append("Die Authentifizierung (SPF/DKIM/DMARC) ist fehlgeschlagen oder nicht vorhanden.")
        if any('anzeigename passt nicht' in d.lower() for d in technical_results):
            user_reasons.append("Der Anzeigename passt nicht zur Absenderdomain.")
        if any('brand-impersonation' in d.lower() for d in technical_results):
            user_reasons.append("Der Anzeigename imitiert eine bekannte Marke.")
        if any('reply-to-domain' in d.lower() for d in technical_results):
            user_reasons.append("Reply-To weicht von der Absenderdomain ab.")
        if any('zeitdruck' in d.lower() for d in technical_results):
            user_reasons.append("Die E-Mail setzt künstlichen Zeitdruck (z.B. 'jetzt', 'sofort').")
        if is_domain_known_phishing(base_domain):
            user_reasons = ["Die Absenderdomain ist als Phishing-Domain bekannt."]
        if not user_reasons:
            user_reasons = ["Keine spezifischen Auffälligkeiten festgestellt."]

        try:
            os.remove(filepath)
        except Exception as e:
            logging.error("Error removing uploaded file: %s", e)

        return render_template(
            'result.html',
            analysis={
                'phishing_probability': final_score,
                'color': color,
                'why_message': user_reasons,
                'From': from_header,
                'Subject': msg.get('Subject',''),
                'To': msg.get('To',''),
                'Date': msg.get('Date',''),
                'Reply-To': reply_to,
                'URLs': urls,
            }
        )
    return render_template('index.html')

if __name__ == '__main__':
    app.run()
