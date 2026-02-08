from trust_engine import evaluate_trust
from logger import log_alert

# 802.11 deauthentication frame subtype
DEAUTH_SUBTYPE = 0x0C

def analyze_packet(packet):
    if packet.type == 0 and packet.subtype == DEAUTH_SUBTYPE:
        src_mac = packet.addr2

        log_alert(
            threat="Wireless Deauthentication Attack",
            mac=src_mac,
            mitre_technique="T1040"
        )

        evaluate_trust(src_mac)

