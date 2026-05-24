import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, UTC
from pathlib import Path

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeReq

from trust_engine import evaluate_trust, load_config
from logger import log_alert


DETECTION_RULES_FILE = Path("config/detection_rules.json")

deauth_events = defaultdict(deque)
beacon_events = defaultdict(deque)


def load_detection_rules():
    with open(DETECTION_RULES_FILE, "r") as file:
        return json.load(file)

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

def detect_unknown_mac(packet):
    rules = load_detection_rules()
    rule = rules.get("unknown_mac", {})

    if not rule.get("enabled", True):
        return

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
            severity=rule.get("severity", "HIGH"),
            mitre_technique=rule.get("mitre_technique", "Initial Access / Rogue Device concept"),
            action="Flagged unknown device",
            details={
                "source_mac": src_mac,
                "zero_trust_decision": "not_trusted"
            }
        )

def detect_deauth_flood(packet):
    rules = load_detection_rules()
    rule = rules.get("deauth_flood", {})

    if not rule.get("enabled", True):
        return

    if not packet.haslayer(Dot11Deauth):
        return

    src_mac = packet.addr2 or "UNKNOWN"
    target_mac = packet.addr1 or "UNKNOWN"

    window_seconds = rule.get("window_seconds", 60)
    threshold = rule.get("threshold", 5)

    deauth_events[src_mac].append(_now())
    _cleanup_old_events(deauth_events[src_mac], window_seconds)

    event_count = len(deauth_events[src_mac])

    if event_count >= threshold:
        log_alert(
            threat="Wireless Deauthentication Flood",
            mac=src_mac,
            severity=rule.get("severity", "HIGH"),
            mitre_technique=rule.get("mitre_technique", "Impact / Network DoS concept"),
            action="Threshold exceeded",
            details={
                "source_mac": src_mac,
                "target_mac": target_mac,
                "event_count": event_count,
                "threshold": threshold,
                "window_seconds": window_seconds
            }
        )

        evaluate_trust(
            src_mac,
            reason=f"Deauthentication flood detected: {event_count} events in {window_seconds}s"
        )

def detect_evil_twin(packet):
    rules = load_detection_rules()
    rule = rules.get("evil_twin", {})

    if not rule.get("enabled", True):
        return

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
            severity=rule.get("severity", "HIGH"),
            mitre_technique=rule.get("mitre_technique", "Credential Access / Rogue AP concept"),
            action="SSID matches trusted network but BSSID is untrusted",
            details={
                "ssid": ssid,
                "observed_bssid": bssid,
                "expected_bssid": trusted_ssids[ssid]
            }
        )


def detect_beacon_flood(packet):
    rules = load_detection_rules()
    rule = rules.get("beacon_flood", {})

    if not rule.get("enabled", True):
        return

    if not packet.haslayer(Dot11Beacon):
        return

    bssid = packet.addr3 or "UNKNOWN"

    window_seconds = rule.get("window_seconds", 60)
    threshold = rule.get("threshold", 10)

    beacon_events[bssid].append(_now())
    _cleanup_old_events(beacon_events[bssid], window_seconds)

    event_count = len(beacon_events[bssid])

    if event_count >= threshold:
        log_alert(
            threat="Beacon Flood Detected",
            mac=bssid,
            severity=rule.get("severity", "MEDIUM"),
            mitre_technique=rule.get("mitre_technique", "Impact / Wireless DoS concept"),
            action="Beacon threshold exceeded",
            details={
                "bssid": bssid,
                "event_count": event_count,
                "threshold": threshold,
                "window_seconds": window_seconds
            }
        )

def detect_probe_request(packet):
    rules = load_detection_rules()
    rule = rules.get("probe_request", {})

    if not rule.get("enabled", True):
        return

    if not packet.haslayer(Dot11ProbeReq):
        return

    src_mac = packet.addr2 or "UNKNOWN"

    log_alert(
        threat="Probe Request Observed",
        mac=src_mac,
        severity=rule.get("severity", "LOW"),
        mitre_technique=rule.get("mitre_technique", "Discovery / Wireless Recon concept"),
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
