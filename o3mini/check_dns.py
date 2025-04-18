import dns.resolver
import socket
import re
import time

# Gewichtungen bleiben wie gehabt
NO_A_RECORD = 10
NO_MX = 15
PUNYCODE_DOMAIN = 30
TLD_SUSPECT = 15

# Einfacher Cache (Dauer: 10 Minuten)
_dns_cache = {}
CACHE_TIMEOUT = 600  # Sekunden

def get_cached(key):
    entry = _dns_cache.get(key)
    if entry and time.time() - entry[1] < CACHE_TIMEOUT:
        return entry[0]
    return None

def set_cached(key, value):
    _dns_cache[key] = (value, time.time())

def is_punycode(domain):
    return domain.startswith("xn--")

def has_suspect_tld(domain):
    suspect_tlds = ['.click', '.xyz', '.top', '.monster', '.buzz', '.fit', '.gq', '.ml']
    return any(domain.endswith(tld) for tld in suspect_tlds)

def check_dns(domain):
    score = 0
    details = []
    
    cache_key = f"dns_{domain}"
    cached_result = get_cached(cache_key)
    if cached_result is not None:
        return cached_result

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

    result = (score, details)
    set_cached(cache_key, result)
    return result
