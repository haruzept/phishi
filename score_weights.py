# score_weights.py – Bewertungskriterien und Gewichtung

DKIM_FAIL = 25
SPF_FAIL = 25
DMARC_FAIL = 25

NO_A_RECORD = 20
NO_MX = 25

FREEMAIL_REPLY_TO = 15
DISPLAY_NAME_MISMATCH = 10
PUNYCODE_DOMAIN = 10
TLD_SUSPECT = 10
LINK_CONTAINS_IP = 15
SUSPICIOUS_LINK_TEXT = 10

WHOIS_TOO_NEW = 20
WHOIS_NOT_FOUND = 25

def get_color_for_score(score: int) -> tuple[str, str]:
    if score >= 60:
        ret = ("Rot", "Diese E-Mail ist hochverdächtig. Wenden Sie sich ggf. an Ihre IT-Abteilung.")
    elif score >= 25:
        ret = ("Orange", "Diese E-Mail enthält Auffälligkeiten. Bitte prüfen Sie sie sorgfältig oder wenden Sie sich an Ihre IT-Abteilung.")
    else:
        ret = ("Grün", "Diese E-Mail erscheint unbedenklich.")

    # Debug-Ausgabe zur Kontrolle
    print("DEBUG: get_color_for_score returns", ret)
    return ret
