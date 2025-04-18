import os
import logging
import yaml
import bleach
from flask import Flask, render_template, request, flash
from werkzeug.utils import secure_filename
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import sqlite3
import redis
from kombu.exceptions import OperationalError

from celery_app import celery
from tasks import dns_check_task, whois_check_task

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Load configuration
with open('config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "phishi"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def extract_domain(email_address):
    parts = email_address.split('@')
    return parts[1].lower() if len(parts) == 2 else ""

def extract_urls(msg):
    urls = []
    url_regex = re.compile(r'https?://[^\s"\'<>]+')
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain','text/html']:
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

def sanitize(text):
    return bleach.clean(text)

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
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        logging.error("Error accessing phishing database: %s", e)
        return False

def get_enduser_explanation(score):
    if score == 0:
        return ["Die Analyse ergab keinerlei Auffälligkeiten.","Diese E-Mail scheint echt zu sein."]
    elif score < 25:
        return ["Nur wenige Auffälligkeiten.","E-Mail wirkt wahrscheinlich echt, dennoch vorsichtig sein."]
    elif score < 60:
        return ["Einige Indizien für Manipulation.","E-Mail genauer prüfen."]
    else:
        return ["Mehrere Merkmale deuten stark auf Phishing hin.","Besonders vorsichtig sein."]

@app.route('/', methods=['GET','POST'])
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

        with open(filepath,'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # extract headers
        raw_headers = get_headers_str(msg)
        auth_results_header = msg.get('Authentication-Results','')
        dkim_signature_header = msg.get('DKIM-Signature','')
        received_spf_header = msg.get('Received-SPF','')

        from_header = msg.get('From','')
        display_name, email_address = parseaddr(from_header)
        base_domain = get_base_domain(extract_domain(email_address))
        reply_to_header = msg.get('Reply-To', '')

        # Async DNS/WHOIS with fallback
        try:
            dns_async = dns_check_task.delay(base_domain)
            whois_async = whois_check_task.delay(base_domain)
            dns_score, dns_details = dns_async.get(timeout=10)
            whois_score, whois_details = whois_async.get(timeout=10)
            logging.info("Celery tasks executed successfully")
        except (redis.exceptions.ConnectionError, OperationalError, celery.exceptions.TimeoutError) as e:
            logging.warning("Async tasks failed (%s), falling back to sync execution", e)
            from check_dns import check_dns
            from check_whois import check_domain_age
            dns_score, dns_details = check_dns(base_domain)
            whois_score, whois_details = check_domain_age(base_domain)

        technical_results = dns_details + whois_details
        total_score = dns_score + whois_score

        # SPF/DKIM/DMARC
        auth = auth_results_header.lower()
        if 'spf=fail' in auth:
            total_score += config['weights']['spf_fail']; technical_results.append("SPF fail")
        if 'dkim=fail' in auth:
            total_score += config['weights']['dkim_fail']; technical_results.append("DKIM fail")
        if 'dmarc=fail' in auth:
            total_score += config['weights']['dmarc_fail']; technical_results.append("DMARC fail")

        # Brand impersonation
        for br in config['brands']:
            if br in display_name.lower() and br not in base_domain.lower():
                total_score += config['weights']['brand_impersonation']
                technical_results.append(f"Brand mismatch {br}")

        # Reply-To mismatch (only count if reply-to domain ≠ from domain)
        if reply_to_header:
            rt_domain = extract_domain(reply_to_header)
            if rt_domain != base_domain:
                total_score += config['weights']['reply_to_mismatch']
                technical_results.append("Reply-To weicht von der Absenderdomain ab.")

        # Link checks
        urls = extract_urls(msg)
        if urls:
            from check_links import check_links
            link_score, link_details = check_links(urls, expected_domain=base_domain)
            total_score += link_score
            technical_results.extend(link_details)
        else:
            technical_results.append("Keine URLs gefunden")

        # Known phishing domain
        if is_domain_known_phishing(base_domain):
            final_score = 100
            technical_results.append("Domain in database")
        else:
            final_score = min(total_score,100)

        # Color
        if final_score < config['thresholds']['green']:
            color = 'green'
        elif final_score < config['thresholds']['orange']:
            color = 'orange'
        else:
            color = 'red'

        # Prepare result dict (including all technical fields)
        result = {
            'phishing_probability': final_score,
            'color': color,
            'why_message': get_enduser_explanation(final_score),
            'score_details': technical_results,
            'raw_headers': raw_headers,
            'authentication_results_header': auth_results_header,
            'dkim_signature_header': dkim_signature_header,
            'received_spf_header': received_spf_header,
            'From': from_header,
            'Subject': msg.get('Subject',''),
            'To': msg.get('To',''),
            'Date': msg.get('Date',''),
            'Reply-To': reply_to_header,
            'URLs': urls
        }

        try:
            os.remove(filepath)
        except OSError as e:
            logging.error("Error removing uploaded file: %s", e)

        return render_template('result.html', analysis=result)

    return render_template('index.html')

if __name__ == '__main__':
    app.run()
