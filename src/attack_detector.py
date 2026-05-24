from collections import defaultdict, deque
from datetime import datetime, timedelta, UTC

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeReq

from trust_engine import evaluate_trust, load_config
from logger import log_alert


DEAUTH_WINDOW_SECONDS = 60
DEAUTH_THRESHOLD = 5
BEACON_WINDOW_SECONDS = 60
BEACON_THRESHOLD = 10

deauth_events = defaultdict(deque)
beacon_events = defaultdict(deque)


def _now():
	return datetime.now(UTC)

def _cleanup_old_events(event_queue, window_seconds):
    cutoff = _now() - timedelta(seconds=window_seconds)

    while event_queue and event_queue[0] < cutoff:
        event_queue.popleft()


def _get_trusted_macs():
    config = load_config()
    return {
        device["mac"].upper()
        for device in config.get("trusted_devices", [])
    }


def _get_trusted_ssids():
    config = load_config()
    return {
        item["ssid"]: item["bssid"].upper()
        for item in config.get("trusted_ssids", [])
    }


def detect_unknown_mac(packet):
    if not packet.haslayer(Dot11):
        return

    src_mac = packet.addr2

    if not src_mac:
        return

    trusted_macs = _get_trusted_macs()

    if src_mac.upper() not in trusted_macs and src_mac.lower() != "ff:ff:ff:ff:ff:ff":
        log_alert(
            threat="Unknown Wireless Device",
            mac=src_mac,
            severity="HIGH",
            mitre_technique="Initial Access / Rogue Device concept",
            action="Flagged unknown device",
            details={
                "source_mac": src_mac,
                "zero_trust_decision": "not_trusted"
            }
        )


def detect_deauth_flood(packet):
    if not packet.haslayer(Dot11Deauth):
        return

    src_mac = packet.addr2 or "UNKNOWN"
    target_mac = packet.addr1 or "UNKNOWN"

    deauth_events[src_mac].append(_now())
    _cleanup_old_events(deauth_events[src_mac], DEAUTH_WINDOW_SECONDS)

    event_count = len(deauth_events[src_mac])

    if event_count >= DEAUTH_THRESHOLD:
        log_alert(
            threat="Wireless Deauthentication Flood",
            mac=src_mac,
            severity="HIGH",
            mitre_technique="Impact / Network DoS concept",
            action="Threshold exceeded",
            details={
                "source_mac": src_mac,
                "target_mac": target_mac,
                "event_count": event_count,
                "window_seconds": DEAUTH_WINDOW_SECONDS
            }
        )

        evaluate_trust(
            src_mac,
            reason=f"Deauthentication flood detected: {event_count} events in {DEAUTH_WINDOW_SECONDS}s"
        )


def detect_evil_twin(packet):
    if not packet.haslayer(Dot11Beacon):
        return

    ssid = None

    try:
        ssid = packet.info.decode(errors="ignore")
    except Exception:
        ssid = None

    bssid = packet.addr3

    if not ssid or not bssid:
        return

    trusted_ssids = _get_trusted_ssids()

    if ssid in trusted_ssids and trusted_ssids[ssid] != bssid.upper():
        log_alert(
            threat="Possible Evil Twin Access Point",
            mac=bssid,
            severity="HIGH",
            mitre_technique="Credential Access / Rogue AP concept",
            action="SSID matches trusted network but BSSID is untrusted",
            details={
                "ssid": ssid,
                "observed_bssid": bssid,
                "expected_bssid": trusted_ssids[ssid]
            }
        )


def detect_beacon_flood(packet):
    if not packet.haslayer(Dot11Beacon):
        return

    bssid = packet.addr3 or "UNKNOWN"

    beacon_events[bssid].append(_now())
    _cleanup_old_events(beacon_events[bssid], BEACON_WINDOW_SECONDS)

    event_count = len(beacon_events[bssid])

    if event_count >= BEACON_THRESHOLD:
        log_alert(
            threat="Beacon Flood Detected",
            mac=bssid,
            severity="MEDIUM",
            mitre_technique="Impact / Wireless DoS concept",
            action="Beacon threshold exceeded",
            details={
                "bssid": bssid,
                "event_count": event_count,
                "window_seconds": BEACON_WINDOW_SECONDS
            }
        )


def detect_probe_request(packet):
    if not packet.haslayer(Dot11ProbeReq):
        return

    src_mac = packet.addr2 or "UNKNOWN"

    log_alert(
        threat="Probe Request Observed",
        mac=src_mac,
        severity="LOW",
        mitre_technique="Discovery / Wireless Recon concept",
        action="Logged probe request",
        details={
            "source_mac": src_mac
        }
    )


def analyze_packet(packet):
    """
    Analyze wireless packets for multiple detection conditions.
    """

    detect_unknown_mac(packet)
    detect_deauth_flood(packet)
    detect_evil_twin(packet)
    detect_beacon_flood(packet)
    detect_probe_request(packet)
