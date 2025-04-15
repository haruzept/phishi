import re
LINK_CONTAINS_IP = 25
FREEMAIL_BUSINESS = 20

FREEMAIL_DOMAINS = {
    "gmail.com", "gmx.net", "web.de", "hotmail.com", "yahoo.com", "outlook.com", "live.com", "aol.com"
}

def check_links(urls):
    score = 0
    details = []
    ip_regex = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?=/|:|$)')

    for url in urls:
        if ip_regex.search(url):
            score += LINK_CONTAINS_IP
            details.append(f"Link {url} enthält eine IP-Adresse anstelle einer Domain.")

    return score, details

def check_freemailer_abuse(from_domain, display_name):
    score = 0
    details = []
    if from_domain in FREEMAIL_DOMAINS and display_name and display_name not in from_domain:
        score += FREEMAIL_BUSINESS
        details.append(f"Absender verwendet eine Freemail-Adresse ({from_domain}), aber abweichenden Anzeigenamen ({display_name}).")
    return score, details
