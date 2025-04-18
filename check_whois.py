import subprocess,re, pickle, redis
from config import config

cache = redis.Redis()
def get_cache(k):
    v = cache.get(k)
    return pickle.loads(v) if v else None
def set_cache(k,v):
    cache.set(k,pickle.dumps(v),ex=600)

def extract_tld(d):
    p=d.split('.')
    return '.'.join(p[-2:]) if len(p)>2 else d

def check_domain_age(domain):
    tld=extract_tld(domain)
    key=f"whois:{tld}"
    cached=get_cache(key)
    if cached: return cached
    s,det=0,[]
    try:
        o=subprocess.run(["whois",tld],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5).stdout.lower()
        m=re.search(r"creation date:\s*(\d{4}-\d{2}-\d{2})",o)
        if m: det.append(f"Created {m.group(1)}")
        else: s+=config['weights']['whois_too_new']; det.append("no create")
    except Exception as e:
        s+=config['weights']['whois_not_found']; det.append("whois error")
    res=(s,det); set_cache(key,res); return res
