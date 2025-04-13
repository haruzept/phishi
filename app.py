from flask import Flask, request, render_template, redirect, flash
import email
from email import policy
from email.parser import BytesParser
import re

app = Flask(__name__)
app.secret_key = "dein_geheimer_schluessel"  # Wähle einen sicheren Secret Key

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Check, ob eine Datei hochgeladen wurde
        if 'email_file' not in request.files:
            flash("Keine Datei ausgewählt.")
            return redirect(request.url)
        file = request.files["email_file"]
        if file.filename == "":
            flash("Keine Datei ausgewählt.")
            return redirect(request.url)
        
        try:
            # Die Datei wird direkt aus dem File-Stream geparst
            msg = BytesParser(policy=policy.default).parse(file)
        except Exception as e:
            return f"Fehler beim Parsen der E-Mail: {e}"
        
        # Analyse der E-Mail anhand von Header-Daten und URL-Suche
        analysis_result = analyze_email(msg)
        return render_template("result.html", analysis=analysis_result)
        
    return render_template("index.html")

def analyze_email(msg):
    results = {}
    
    # Basisinformationen aus den Headern extrahieren
    results["Subject"] = msg.get("Subject", "Kein Subject")
    results["From"] = msg.get("From", "Unbekannt")
    results["To"] = msg.get("To", "Unbekannt")
    results["Date"] = msg.get("Date", "Unbekannt")
    
    # Reply-To-Header, falls vorhanden
    reply_to = msg.get("Reply-To", "")
    results["Reply-To"] = reply_to if reply_to else "Nicht vorhanden"
    
    # Beispielregel: Falls der Absender "DHL" im Namen enthält, muss die Domain dhl.de sein
    sender = msg.get("From", "")
    if sender:
        match = re.search(r"@([\w\.-]+)", sender)
        if match:
            domain = match.group(1)
            if "dhl" in sender.lower():
                if domain.lower() != "dhl.de":
                    results["Warning"] = "DHL E-Mail kommt nicht von einer dhl.de Adresse!"
                else:
                    results["Warning"] = "Absender-Domain stimmt."
            else:
                results["Warning"] = "Kein spezifischer Test für den Absender durchgeführt."
        else:
            results["Warning"] = "Absender-Domain konnte nicht extrahiert werden."
    else:
        results["Warning"] = "Keine Absender-Information vorhanden."
    
    # Ausgewählte Received-Header anzeigen (limitierte Ausgabe)
    received_headers = msg.get_all("Received")
    if received_headers:
        results["Received"] = "\n".join(received_headers[:3])
    else:
        results["Received"] = "Keine Received-Header vorhanden."
    
    # E-Mail-Body analysieren: Falls vorhanden, werden alle URLs gesucht
    body = ""
    if msg.is_multipart():
        # Für Multipart-E-Mails wird der Teil mit content-type "text/plain" extrahiert
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()
    
    results["URLs"] = extract_urls(body)
    
    return results

def extract_urls(text):
    # Einfache Regex zur Suche nach http/https-URLs
    url_regex = re.compile(r'https?://[^\s]+')
    urls = url_regex.findall(text)
    return urls if urls else ["Keine URLs gefunden"]

if __name__ == "__main__":
    app.run(debug=True)
