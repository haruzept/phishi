
# Bewertungskonfiguration für Phishing-Analyse

# Positivfaktoren (ziehen Punkte AB = gut)
SPF_PASS = -5
DKIM_PASS = -5
DMARC_PASS = -5
SPF_STRICT = -5     # SPF-Hardfail via '-all'
DMARC_POLICY_REJECT = -5

# Negativfaktoren (erhöhen Punkte = verdächtig)
SPF_FAIL = +10
DKIM_FAIL = +10
DMARC_FAIL = +10
NO_MX = +15
NO_A_RECORD = +20
DOMAIN_YOUNG_30 = +30
DOMAIN_YOUNG_90 = +15
TLD_SUSPECT = +15
LINK_CONTAINS_IP = +25
DISPLAYNAME_MISMATCH = +30
REPLYTO_MISMATCH = +25
FREEMAIL_BUSINESS = +20
PUNYCODE_DOMAIN = +30
