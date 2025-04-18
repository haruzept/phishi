# check_whois.py

import subprocess
import re
import pickle
import time
import shutil
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


def extract_tld(domain):
    parts = domain.split('.')
    return '.'.join(parts[-2:]) if len(parts) > 2 else domain


def check_domain_age(domain):
    tld = extract_tld(domain)
    key = f"whois:{tld}"
    cached = get_cached(key)
    if cached:
        return cached

    score = 0
    details = []

    # Finde die whois-Binärdatei
    whois_bin = shutil.which('whois') or '/usr/bin/whois'
    if not shutil.which('whois'):
        details.append(f"Whois-Binary nicht gefunden ({whois_bin}).")
        score += config['weights']['whois_not_found']
        result = (score, details)
        set_cached(key, result)
        return result

    try:
        proc = subprocess.run(
            [whois_bin, tld],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        output = proc.stdout.lower()

        # DE-Domain: Changed-Datum
        if tld.endswith(".de"):
            match = re.search(r"changed:\s*(\d{4}-\d{2}-\d{2})", output)
            if match:
                details.append(f"Whois-Abfrage: Changed am {match.group(1)}")
            else:
                score += config['weights']['whois_too_new']
                details.append(f"Whois-Abfrage: Kein Changed-Datum für {tld} verfügbar.")
        else:
            # internationale Domains: Creation Date
            match = re.search(r"creation date:\s*(\d{4}-\d{2}-\d{2})", output)
            if match:
                details.append(f"Whois-Abfrage: Creation Date am {match.group(1)}")
            else:
                score += config['weights']['whois_too_new']
                details.append(f"Whois-Abfrage: Kein Creation Date für {tld} gefunden.")

    except subprocess.TimeoutExpired:
        score += config['weights']['whois_not_found']
        details.append(f"Whois-Abfrage für {tld} abgebrochen (Timeout).")
    except Exception as e:
        score += config['weights']['whois_not_found']
        details.append(f"Fehler bei der Whois-Abfrage für {tld}: {e}")

    result = (score, details)
    set_cached(key, result)
    return result
