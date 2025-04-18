# check_dns.py

import socket
import dns.resolver
import pickle
import time
from config import config

# Versuche Redis zu importieren, sonst kein Cache
try:
    import redis
    _cache = redis.Redis()
except Exception:
    _cache = None

CACHE_TIMEOUT = 600  # Sekunden

def get_cached(key):
    if not _cache:
        return None
    try:
        raw = _cache.get(key)
        if raw:
            val, ts = pickle.loads(raw)
            if time.time() - ts < CACHE_TIMEOUT:
                return val
    except Exception:
        pass
    return None

def set_cached(key, value):
    if not _cache:
        return
    try:
        raw = pickle.dumps((value, time.time()))
        _cache.set(key, raw, ex=CACHE_TIMEOUT)
    except Exception:
        pass

def is_punycode(domain):
    return domain.startswith("xn--")

def has_suspect_tld(domain):
    suspect_tlds = ['.click', '.xyz', '.top', '.monster', '.buzz', '.fit', '.gq', '.ml']
    return any(domain.endswith(tld) for tld in suspect_tlds)

def check_dns(domain):
    key = f"dns:{domain}"
    cached = get_cached(key)
    if cached:
        return cached

    score = 0
    details = []

    # A-Record
    try:
        socket.gethostbyname(domain)
    except Exception:
        score += config['weights']['no_a_record']
        details.append(f"Domain {domain} hat keinen gültigen A-Record.")

    # MX-Record
    try:
        dns.resolver.resolve(domain, 'MX')
    except Exception:
        score += config['weights']['no_mx']
        details.append(f"Domain {domain} hat keinen gültigen MX-Record.")

    # Punycode
    if is_punycode(domain):
        score += config['weights']['punycode_domain']
        details.append(f"Domain {domain} verwendet Punycode (möglicher Homograph-Angriff).")

    # Verdächtige TLD
    if has_suspect_tld(domain):
        score += config['weights']['tld_suspect']
        details.append(f"Domain {domain} verwendet eine verdächtige TLD.")

    result = (score, details)
    set_cached(key, result)
    return result
