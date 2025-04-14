
import subprocess
from datetime import datetime, timezone
from score_weights import DOMAIN_YOUNG_30, DOMAIN_YOUNG_90

def parse_creation_date_from_cli_output(output):
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if any(keyword in line.lower() for keyword in ["creation date", "created", "created on", "created-date"]):
            parts = line.split(":", 1)
            if len(parts) == 2:
                date_str = parts[1].strip()
                try:
                    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")  # ISO format
                except:
                    try:
                        return datetime.strptime(date_str, "%Y-%m-%d")
                    except:
                        try:
                            return datetime.strptime(date_str, "%d.%m.%Y")
                        except:
                            continue
    return None

def check_domain_age(domain):
    score = 0
    details = []
    creation = None

    # Versuch 1: python-whois
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
    except Exception as e:
        details.append(f"Python-Whois fehlgeschlagen: {e}")

    # Versuch 2: CLI fallback
    if not creation:
        try:
            out = subprocess.check_output(["whois", domain], timeout=5, text=True, stderr=subprocess.DEVNULL)
            creation = parse_creation_date_from_cli_output(out)
        except Exception as e:
            details.append(f"CLI-Whois fehlgeschlagen: {e}")

    # Bewertung
    if creation is None:
        details.append(f"Whois-Abfrage: Kein Erstellungsdatum für {domain} verfügbar.")
        return score, details

    if isinstance(creation, datetime):
        age_days = (datetime.now(timezone.utc) - creation).days
        if age_days <= 30:
            score += DOMAIN_YOUNG_30
            details.append(f"Domain {domain} ist jünger als 30 Tage (nur {age_days} Tage alt).")
        elif age_days <= 90:
            score += DOMAIN_YOUNG_90
            details.append(f"Domain {domain} ist jünger als 90 Tage (nur {age_days} Tage alt).")

    return score, details
