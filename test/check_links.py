import re
from urllib.parse import urlparse

LINK_CONTAINS_IP = 25

def get_base_domain(domain):
    """
    Extrahiert die Basisdomain aus einem Domainnamen 
    (z. B. aus notice.aliexpress.com → aliexpress.com).
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

def check_links(urls, expected_domain=""):
    """
    Prüft die in der E-Mail gefundenen URLs.
    - Wenn ein Link eine IP-Adresse enthält, wird ein hoher Score vergeben.
    Externe Domains (d.h. Links, deren Basisdomain nicht expected_domain entspricht)
    werden NICHT bestraft.
    """
    score = 0
    details = []
    ip_regex = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?=/|:|$)')
    for url in urls:
        if ip_regex.search(url):
            score += LINK_CONTAINS_IP
            details.append(f"Link {url} enthält eine IP-Adresse anstelle einer Domain.")
    return score, details
