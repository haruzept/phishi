import sqlite3
import requests
from datetime import datetime

# Verbindet sich mit einer vorhandenen SQLite-Datenbank
conn = sqlite3.connect("phishing_data.db")
cursor = conn.cursor()

# Beispielquelle: Phishing.Database (nur Domains, öffentlich & CC0)
PHISHING_DB_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
SOURCE_NAME = "Phishing.Database"

def update_source_metadata(source_name, url):
    from datetime import datetime, UTC
    now = datetime.now(UTC).isoformat()
    cursor.execute("SELECT id FROM phishing_sources WHERE source_name = ?", (source_name,))
    if cursor.fetchone():
        cursor.execute("UPDATE phishing_sources SET last_updated = ? WHERE source_name = ?", (now, source_name))
    else:
        cursor.execute("INSERT INTO phishing_sources (source_name, source_url, last_updated) VALUES (?, ?, ?)", 
                       (source_name, url, now))
    conn.commit()

def fetch_and_update_domains(url, source_name):
    response = requests.get(url)
    response.raise_for_status()
    
    content = response.text
    for line in content.strip().splitlines():
        domain = line.strip()
        if domain and not domain.startswith("#"):
            from datetime import datetime, UTC
            now = datetime.now(UTC).isoformat()
            try:
                cursor.execute("""
                    INSERT INTO phishing_domains (domain, first_seen, last_seen, source)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET last_seen = excluded.last_seen
                """, (domain, now, now, source_name))
            except sqlite3.Error as e:
                print(f"Fehler beim Einfügen/Aktualisieren der Domain {domain}: {e}")
    conn.commit()

# Hauptlogik
update_source_metadata(SOURCE_NAME, PHISHING_DB_URL)
fetch_and_update_domains(PHISHING_DB_URL, SOURCE_NAME)

# Verbindung schließen
conn.close()
