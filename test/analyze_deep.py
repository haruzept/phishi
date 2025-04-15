import os
from flask import Flask, render_template, request, flash
from werkzeug.utils import secure_filename
from email import policy
from email.parser import BytesParser
from check_dns import check_dns
from check_links import check_links
from check_whois import check_domain_age
from score_weights import get_color_for_score  # calculate_score wurde entfernt

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "phishi"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_email(msg):
    technical_results = []
    total_score = 0

    from_header = msg['From'] or ""
    from_domain = extract_domain_from_header(from_header)

    # Prüfe die E-Mail anhand verschiedener Funktionen.
    # Für check_links wird das ganze Message-Objekt übergeben,
    # für die anderen nur die Domain.
    for check_func in [check_dns, check_domain_age, check_links]:
        score, details = check_func(from_domain if check_func != check_links else msg)
        technical_results.extend(details)
        total_score += score

    # Anzeigename-Mismatch-Prüfung:
    if from_header and from_domain and from_domain not in from_header:
        technical_results.append(f"Anzeigename passt nicht zur Domain: {from_header} ≠ {from_domain}")
        total_score += 10

    # Den akkumulierten numerischen Score nutzen:
    score = total_score

    # Debug-Ausgabe: Überprüfe, was get_color_for_score zurückgibt
    color_result = get_color_for_score(score)
    print("DEBUG: analyze_email obtained get_color_for_score returns:", color_result)
    color, color_hint = color_result

    return {
        "phishing_probability": score,
        "phishing_color": color,
        "phishing_hint": color_hint,
        "score_details": technical_results,
        "From": from_header,
        "Subject": msg.get("Subject", ""),
        "To": msg.get("To", ""),
        "Date": msg.get("Date", ""),
        "Reply-To": msg.get("Reply-To", "")
    }

def extract_domain_from_header(header):
    import re
    match = re.search(r'@([\w\.-]+)', header or "")
    return match.group(1).lower() if match else ""

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
            return render_template('result.html', analysis=analysis_result)

        flash("Ungültiger Dateityp. Bitte eine .eml-Datei hochladen.")
        return render_template('index.html')

    return render_template('index.html')

if __name__ == '__main__':
    app.run()
