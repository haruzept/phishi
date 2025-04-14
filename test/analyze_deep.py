
import os
import sqlite3
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from email import policy
from email.parser import BytesParser
from check_whois import check_domain_age  # wichtig: Funktion muss korrekt importierbar sein
from check_links import check_links
from check_dns import check_dns
from score_weights import calculate_score

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_email(msg):
    technical_results = []

    # FROM
    from_header = msg['From']
    if from_header:
        from_domain = from_header.split('@')[-1].replace('>', '').strip()
    else:
        from_domain = "Unbekannt"

    # Check DNS (SPF, DKIM, DMARC)
    dns_score, dns_results = check_dns(msg)
    technical_results.extend(dns_results)

    # Check WHOIS (Domain-Alter)
    whois_score, whois_results = check_domain_age(from_domain)
    technical_results.extend(whois_results)

    # Check Links
    link_score, link_results = check_links(msg)
    technical_results.extend(link_results)

    # Anzeige-Name vs Domain
    display_name = msg.get('From', '')
    if '<' in display_name and '>' in display_name:
        display_part = display_name.split('<')[0].strip().strip('"')
        if display_part and from_domain not in display_part:
            technical_results.append(f"Anzeigename '{display_part}' passt nicht zur Domain '{from_domain}'.")
            link_score += 1

    # Gesamtbewertung
    final_score = calculate_score(dns_score, whois_score, link_score)

    return final_score, technical_results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "Keine Datei hochgeladen"
        file = request.files['file']
        if file.filename == '':
            return "Keine Datei ausgewählt"
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            with open(filepath, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)

            score, analysis_result = analyze_email(msg)
            return render_template('result.html', score=score, result=analysis_result, msg=msg)
    return render_template('index.html')
