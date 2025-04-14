
import whois
from datetime import datetime, timezone
from score_weights import DOMAIN_YOUNG_30, DOMAIN_YOUNG_90

def check_domain_age(domain):
    score = 0
    details = []
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return 0, ["Whois-Abfrage: Kein Erstellungsdatum verfügbar."]

        if isinstance(creation, datetime):
            age_days = (datetime.now(timezone.utc) - creation).days
            if age_days <= 30:
                score += DOMAIN_YOUNG_30
                details.append(f"Domain {domain} ist jünger als 30 Tage (nur {age_days} Tage alt).")
            elif age_days <= 90:
                score += DOMAIN_YOUNG_90
                details.append(f"Domain {domain} ist jünger als 90 Tage (nur {age_days} Tage alt).")
    except Exception as e:
        details.append(f"Whois-Fehler bei {domain}: {e}")
    return score, details
