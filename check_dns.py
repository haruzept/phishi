import socket, dns.resolver, pickle, redis, time
from config import config

cache = redis.Redis()
def get_cache(k):
    v = cache.get(k)
    return pickle.loads(v) if v else None
def set_cache(k, v):
    cache.set(k, pickle.dumps(v), ex=600)

def is_punycode(d): return d.startswith("xn--")
def has_suspect_tld(d): return any(d.endswith(t) for t in ['.click','.xyz','.top','.monster','.buzz','.fit','.gq','.ml'])

def check_dns(domain):
    key = f"dns:{domain}"
    cached = get_cache(key)
    if cached: return cached
    sc, det = 0, []
    try: socket.gethostbyname(domain)
    except: sc+=config['weights']['no_a_record']; det.append("kein A")
    try: dns.resolver.resolve(domain,'MX')
    except: sc+=config['weights']['no_mx']; det.append("kein MX")
    if is_punycode(domain): sc+=config['weights']['punycode_domain']; det.append("punycode")
    if has_suspect_tld(domain): sc+=config['weights']['tld_suspect']; det.append("sus TLD")
    res=(sc,det); set_cache(key,res); return res
