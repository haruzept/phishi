import subprocess
import re

def extract_tld(domain):
    parts = domain.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return domain

def check_domain_age(domain):
    technical_details = []
    score = 0
    tld = extract_tld(domain)

    try:
        result = subprocess.run(["whois", tld], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        output = result.stdout.lower()

        if ".de" in tld:
            match = re.search(r"changed:\s*(\d{4}-\d{2}-\d{2})", output)
            if match:
                technical_details.append(f"Whois-Abfrage: Changed am {match.group(1)}")
            else:
                technical_details.append(f"Whois-Abfrage: Kein Changed-Datum für {tld} verfügbar.")
                score += 10
        else:
            match = re.search(r"creation date:\s*(\d{4}-\d{2}-\d{2})", output)
            if match:
                technical_details.append(f"Whois-Abfrage: Creation Date am {match.group(1)}")
            else:
                technical_details.append(f"Whois-Abfrage: Kein Creation Date für {tld} gefunden.")
                score += 10
    except subprocess.TimeoutExpired:
        technical_details.append(f"Whois-Abfrage für {tld} abgebrochen (Timeout).")
        score += 10
    except Exception as e:
        technical_details.append(f"Fehler bei der Whois-Abfrage für {tld}: {e}")
        score += 10

    return score, technical_details