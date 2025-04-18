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

from celery_app import celery
from tasks import dns_check_task, whois_check_task
from check_links import check_links

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Load configuration
with open('config.yaml') as f:
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
        if file and allowed_file(file.filename):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(path)
            with open(path,'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            # async tasks
            from_header = msg.get('From','')
            display_name, email_address = parseaddr(from_header)
            base_domain = get_base_domain(extract_domain(email_address))
            dns_async = dns_check_task.delay(base_domain)
            whois_async = whois_check_task.delay(base_domain)
            dns_score, dns_details = dns_async.get(timeout=10)
            whois_score, whois_details = whois_async.get(timeout=10)
            tech = dns_details + whois_details
            total = dns_score + whois_score
            # auth
            auth = msg.get('Authentication-Results','').lower()
            if 'spf=fail' in auth:
                total += config['weights']['spf_fail']; tech.append("SPF fail")
            if 'dkim=fail' in auth:
                total += config['weights']['dkim_fail']; tech.append("DKIM fail")
            if 'dmarc=fail' in auth:
                total += config['weights']['dmarc_fail']; tech.append("DMARC fail")
            # brand
            for br in config['brands']:
                if br in display_name.lower() and br not in base_domain.lower():
                    total += config['weights']['brand_impersonation']; tech.append(f"Brand mismatch {br}")
            # links
            urls = extract_urls(msg)
            if urls:
                l_score, l_det = check_links(urls, expected_domain=base_domain)
                total += l_score; tech += l_det
            else:
                tech.append("Keine URLs gefunden")
            if is_domain_known_phishing(base_domain):
                score = 100; tech.append("Domain in DB")
            else:
                score = min(total,100)
            color = 'green' if score < config['thresholds']['green'] else ('orange' if score < config['thresholds']['orange'] else 'red')
            result = {
                'phishing_probability': score,
                'color': color,
                'explanations': get_enduser_explanation(score),
                'tech': tech,
                'headers': sanitize(str(msg.items())),
                'urls': urls
            }
            os.remove(path)
            return render_template('result.html', res=result)
        flash("Ungültiger Typ"); return render_template('index.html')
    return render_template('index.html')

if __name__=='__main__':
    app.run()
