
import dns.resolver
import socket
import re
from score_weights import NO_A_RECORD, NO_MX, PUNYCODE_DOMAIN, TLD_SUSPECT

def is_punycode(domain):
    return domain.startswith("xn--")

def has_suspect_tld(domain):
    suspect_tlds = ['.click', '.xyz', '.top', '.monster', '.buzz', '.fit', '.gq', '.ml']
    return any(domain.endswith(tld) for tld in suspect_tlds)

def check_dns(domain):
    score = 0
    details = []

    # A-Record
    try:
        socket.gethostbyname(domain)
    except Exception:
        score += NO_A_RECORD
        details.append(f"Domain {domain} hat keinen gültigen A-Record.")

    # MX-Record
    try:
        dns.resolver.resolve(domain, 'MX')
    except Exception:
        score += NO_MX
        details.append(f"Domain {domain} hat keinen gültigen MX-Record.")

    # Punycode
    if is_punycode(domain):
        score += PUNYCODE_DOMAIN
        details.append(f"Domain {domain} verwendet Punycode (möglicher Homograph-Angriff).")

    # TLD prüfen
    if has_suspect_tld(domain):
        score += TLD_SUSPECT
        details.append(f"Domain {domain} verwendet eine verdächtige TLD.")

    return score, details
