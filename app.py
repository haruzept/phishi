def analyze_email(msg):
    results = {}
    
    # Basisinformationen aus den Headern extrahieren
    results["Subject"] = msg.get("Subject", "Kein Subject")
    results["From"] = msg.get("From", "Unbekannt")
    results["To"] = msg.get("To", "Unbekannt")
    results["Date"] = msg.get("Date", "Unbekannt")
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
                    results["Warnung"] = "Auffällig: Absender-Domain stimmt nicht (sollte dhl.de sein)!"
                else:
                    results["Warnung"] = "Absender-Domain ist korrekt."
            else:
                results["Warnung"] = "Kein spezifischer Test für den Absender durchgeführt."
        else:
            results["Warnung"] = "Absender-Domain konnte nicht extrahiert werden."
    else:
        results["Warnung"] = "Keine Absender-Information vorhanden."
    
    # Anzeige der ersten Received-Header (limitierte Ausgabe)
    received_headers = msg.get_all("Received")
    if received_headers:
        results["Received"] = "\n".join(received_headers[:3])
    else:
        results["Received"] = "Keine Received-Header vorhanden."

    # E-Mail-Body analysieren: URLs suchen
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()
    results["URLs"] = extract_urls(body)

    # Berechne anhand der Warnung eine Phishing-Wahrscheinlichkeit:
    # (Dies ist ein simples Beispiel. In einer echten Anwendung sollten komplexere Heuristiken verwendet werden.)
    if "stimmt" in results["Warnung"]:
        results["phishing_probability"] = 10  # z. B. 10% Risiko, wenn alles passt
    else:
        results["phishing_probability"] = 90  # z. B. 90% Risiko, wenn Warnungen vorhanden sind

    return results
