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
    - Zudem werden bekannte URL-Shortener erkannt.
    Externe Domains (d.h. Links, deren Basisdomain nicht expected_domain entspricht)
    werden NICHT bestraft.
    """
    score = 0
    details = []
    ip_regex = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?=/|:|$)')
    url_shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]

    for url in urls:
        if ip_regex.search(url):
            score += LINK_CONTAINS_IP
            details.append(f"Link {url} enthält eine IP-Adresse anstelle einer Domain.")

        # Prüfe, ob die URL einen bekannten Kurzlink-Dienst nutzt
        parsed = urlparse(url)
        if any(short in parsed.netloc.lower() for short in url_shorteners):
            score += 10
            details.append(f"Link {url} verwendet einen URL-Shortener, was verdächtig sein kann.")
    return score, details
