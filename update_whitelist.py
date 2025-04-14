
import sqlite3
import requests

DB_PATH = "phishing_data.db"

# Beispielhafte öffentlich zugängliche Quelle (hier manuell gepflegte Liste via GitHub Gist/Repo)
WHITELIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/whitelist.conf"

def create_whitelist_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            comment TEXT
        )
    """)
    conn.commit()
    conn.close()

def fetch_and_update_whitelist():
    print("Lade Whitelist von", WHITELIST_URL)
    response = requests.get(WHITELIST_URL)
    response.raise_for_status()

    lines = response.text.strip().splitlines()
    new_entries = [line.strip().lower() for line in lines if line and not line.startswith("#")]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    inserted = 0
    for entry in new_entries:
        try:
            c.execute("INSERT OR IGNORE INTO whitelist (type, value, comment) VALUES (?, ?, ?)",
                      ("domain", entry, "Importiert aus öffentlicher Whitelist"))
            inserted += 1
        except Exception as e:
            print("Fehler bei Eintrag:", entry, "→", e)
    conn.commit()
    conn.close()
    print(f"{inserted} neue Einträge eingefügt.")

if __name__ == "__main__":
    create_whitelist_table()
    fetch_and_update_whitelist()
