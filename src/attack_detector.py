from trust_engine import evaluate_trust
from logger import log_alert

# 802.11 deauthentication frame subtype
DEAUTH_SUBTYPE = 0x0C


def analyze_packet(packet):
    """
    Analyze 802.11 wireless frames and detect deauthentication attacks.
    """

    if not hasattr(packet, "type") or not hasattr(packet, "subtype"):
        return

    if packet.type == 0 and packet.subtype == DEAUTH_SUBTYPE:
        src_mac = packet.addr2

        log_alert(
            threat="Wireless Deauthentication Attack",
            mac=src_mac,
            mitre_technique="Impact / Network DoS concept",
            severity="HIGH"
        )



