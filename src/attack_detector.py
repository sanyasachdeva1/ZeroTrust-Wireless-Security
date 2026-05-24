import json
import os
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq

from logger import log_alert
from risk_engine import score_event, severity_from_score
from trust_engine import evaluate_trust, load_config


DEFAULT_DETECTION_RULES_FILE = Path("config/detection_rules.json")

deauth_events = defaultdict(deque)
beacon_events = defaultdict(deque)
alert_cooldowns = {}


def _detection_rules_file():
    return Path(os.environ.get("ZT_DETECTION_RULES_FILE", DEFAULT_DETECTION_RULES_FILE))


def load_detection_rules():
    with open(_detection_rules_file(), "r") as file:
        return json.load(file)


def reset_detection_state():
    deauth_events.clear()
    beacon_events.clear()
    alert_cooldowns.clear()


def _now():
    return datetime.now(UTC)


def _cleanup_old_events(event_queue, window_seconds):
    cutoff = _now() - timedelta(seconds=window_seconds)

    while event_queue and event_queue[0] < cutoff:
        event_queue.popleft()


def _normalize_mac(mac):
    if not mac:
        return None
    return mac.upper()


def _is_broadcast_mac(mac):
    return mac and mac.lower() == "ff:ff:ff:ff:ff:ff"


def _get_trusted_macs():
    config = load_config()
    return {
        device["mac"].upper()
        for device in config.get("trusted_devices", [])
        if device.get("mac")
    }


def _get_trusted_ssids():
    config = load_config()
    trusted_ssids = {}

    for item in config.get("trusted_ssids", []):
        ssid = item.get("ssid")
        if not ssid:
            continue

        bssids = item.get("bssids", [])
        if item.get("bssid"):
            bssids.append(item["bssid"])

        trusted_ssids[ssid] = {
            "bssids": {_normalize_mac(bssid) for bssid in bssids if bssid},
            "channel": item.get("channel"),
            "security": item.get("security"),
        }

    return trusted_ssids


def _get_rule(rules, name):
    return rules.get(name, {})


def _is_rule_enabled(rule):
    return rule.get("enabled", True)


def _should_emit_alert(rule_name, entity, cooldown_seconds):
    if cooldown_seconds <= 0:
        return True

    key = (rule_name, entity)
    current_time = _now()
    last_alert_time = alert_cooldowns.get(key)

    if last_alert_time and current_time - last_alert_time < timedelta(seconds=cooldown_seconds):
        return False

    alert_cooldowns[key] = current_time
    return True


def _get_ssid(packet):
    try:
        ssid_layer = packet.getlayer(Dot11Elt, ID=0)
        if ssid_layer and ssid_layer.info:
            return ssid_layer.info.decode(errors="ignore")
    except Exception:
        pass

    try:
        return packet.info.decode(errors="ignore")
    except Exception:
        return None


def _get_channel(packet):
    try:
        channel_layer = packet.getlayer(Dot11Elt, ID=3)
        if channel_layer and channel_layer.info:
            return int(channel_layer.info[0])
    except Exception:
        return None

    return None


def _get_security(packet):
    try:
        if packet.getlayer(Dot11Elt, ID=48):
            return "WPA2"
    except Exception:
        pass

    try:
        capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
    except Exception:
        capability = ""

    if "privacy" in capability.lower():
        return "WEP_OR_WPA"

    return "OPEN"


def detect_unknown_mac(packet, rules=None):
    rules = rules or load_detection_rules()
    rule = _get_rule(rules, "unknown_mac")

    if not _is_rule_enabled(rule):
        return

    if not packet.haslayer(Dot11):
        return

    src_mac = packet.addr2

    if not src_mac or _is_broadcast_mac(src_mac):
        return

    trusted_macs = _get_trusted_macs()

    if _normalize_mac(src_mac) not in trusted_macs:
        cooldown_seconds = rule.get("cooldown_seconds", 60)
        severity = rule.get("severity", "HIGH")
        risk_score = score_event(severity)

        if not _should_emit_alert("unknown_mac", src_mac, cooldown_seconds):
            return

        log_alert(
            threat="Unknown Wireless Device",
            mac=src_mac,
            severity=severity,
            mitre_technique=rule.get("mitre_technique", "Initial Access / Rogue Device concept"),
            action="Flagged unknown device",
            risk_score=risk_score,
            confidence="medium",
            details={
                "source_mac": src_mac,
                "zero_trust_decision": "not_trusted",
                "cooldown_seconds": cooldown_seconds,
            },
        )


def detect_deauth_flood(packet, rules=None):
    rules = rules or load_detection_rules()
    rule = _get_rule(rules, "deauth_flood")

    if not _is_rule_enabled(rule):
        return

    if not packet.haslayer(Dot11Deauth):
        return

    src_mac = packet.addr2 or "UNKNOWN"
    target_mac = packet.addr1 or "UNKNOWN"

    window_seconds = rule.get("window_seconds", 60)
    threshold = rule.get("threshold", 5)
    cooldown_seconds = rule.get("cooldown_seconds", 60)

    deauth_events[src_mac].append(_now())
    _cleanup_old_events(deauth_events[src_mac], window_seconds)

    event_count = len(deauth_events[src_mac])

    if event_count >= threshold and _should_emit_alert("deauth_flood", src_mac, cooldown_seconds):
        severity = rule.get("severity", "HIGH")
        risk_score = score_event(severity, [min(event_count - threshold, 10)])

        log_alert(
            threat="Wireless Deauthentication Flood",
            mac=src_mac,
            severity=severity_from_score(risk_score),
            mitre_technique=rule.get("mitre_technique", "Impact / Network DoS concept"),
            action="Threshold exceeded",
            risk_score=risk_score,
            confidence="high",
            details={
                "source_mac": src_mac,
                "target_mac": target_mac,
                "event_count": event_count,
                "threshold": threshold,
                "window_seconds": window_seconds,
                "cooldown_seconds": cooldown_seconds,
            },
        )

        evaluate_trust(
            src_mac,
            reason=f"Deauthentication flood detected: {event_count} events in {window_seconds}s",
            risk_score=risk_score,
        )


def detect_evil_twin(packet, rules=None):
    rules = rules or load_detection_rules()
    rule = _get_rule(rules, "evil_twin")

    if not _is_rule_enabled(rule):
        return

    if not packet.haslayer(Dot11Beacon):
        return

    ssid = _get_ssid(packet)
    bssid = packet.addr3
    channel = _get_channel(packet)
    security = _get_security(packet)

    if not ssid or not bssid:
        return

    trusted_ssids = _get_trusted_ssids()
    trusted_network = trusted_ssids.get(ssid)

    if not trusted_network:
        return

    indicators = []

    untrusted_bssid = _normalize_mac(bssid) not in trusted_network["bssids"]

    if untrusted_bssid:
        indicators.append("untrusted_bssid")

    if untrusted_bssid and trusted_network.get("channel") and channel:
        if channel != trusted_network["channel"]:
            indicators.append("channel_mismatch")

    if untrusted_bssid and trusted_network.get("security") and security:
        if security != trusted_network["security"]:
            indicators.append("security_mismatch")

    min_indicators = rule.get("min_indicators", 1)

    if len(indicators) >= min_indicators:
        cooldown_seconds = rule.get("cooldown_seconds", 60)

        if not _should_emit_alert("evil_twin", f"{ssid}:{bssid}", cooldown_seconds):
            return

        severity = rule.get("severity", "HIGH")
        risk_score = score_event(severity, [10 * (len(indicators) - 1)])

        log_alert(
            threat="Possible Evil Twin Access Point",
            mac=bssid,
            severity=severity_from_score(risk_score),
            mitre_technique=rule.get("mitre_technique", "Credential Access / Rogue AP concept"),
            action="Trusted SSID observed with suspicious AP attributes",
            risk_score=risk_score,
            confidence="high" if len(indicators) > 1 else "medium",
            details={
                "ssid": ssid,
                "observed_bssid": bssid,
                "trusted_bssids": sorted(trusted_network["bssids"]),
                "observed_channel": channel,
                "expected_channel": trusted_network.get("channel"),
                "observed_security": security,
                "expected_security": trusted_network.get("security"),
                "indicators": indicators,
                "cooldown_seconds": cooldown_seconds,
            },
        )


def detect_beacon_flood(packet, rules=None):
    rules = rules or load_detection_rules()
    rule = _get_rule(rules, "beacon_flood")

    if not _is_rule_enabled(rule):
        return

    if not packet.haslayer(Dot11Beacon):
        return

    bssid = packet.addr3 or "UNKNOWN"

    window_seconds = rule.get("window_seconds", 60)
    threshold = rule.get("threshold", 10)
    cooldown_seconds = rule.get("cooldown_seconds", 60)

    beacon_events[bssid].append(_now())
    _cleanup_old_events(beacon_events[bssid], window_seconds)

    event_count = len(beacon_events[bssid])

    if event_count >= threshold and _should_emit_alert("beacon_flood", bssid, cooldown_seconds):
        severity = rule.get("severity", "MEDIUM")
        risk_score = score_event(severity, [min(event_count - threshold, 10)])

        log_alert(
            threat="Beacon Flood Detected",
            mac=bssid,
            severity=severity_from_score(risk_score),
            mitre_technique=rule.get("mitre_technique", "Impact / Wireless DoS concept"),
            action="Beacon threshold exceeded",
            risk_score=risk_score,
            confidence="medium",
            details={
                "bssid": bssid,
                "event_count": event_count,
                "threshold": threshold,
                "window_seconds": window_seconds,
                "cooldown_seconds": cooldown_seconds,
            },
        )


def detect_probe_request(packet, rules=None):
    rules = rules or load_detection_rules()
    rule = _get_rule(rules, "probe_request")

    if not _is_rule_enabled(rule):
        return

    if not packet.haslayer(Dot11ProbeReq):
        return

    src_mac = packet.addr2 or "UNKNOWN"
    severity = rule.get("severity", "LOW")
    risk_score = score_event(severity)

    log_alert(
        threat="Probe Request Observed",
        mac=src_mac,
        severity=severity,
        mitre_technique=rule.get("mitre_technique", "Discovery / Wireless Recon concept"),
        action="Logged probe request",
        risk_score=risk_score,
        confidence="low",
        details={
            "source_mac": src_mac,
        },
    )


def analyze_packet(packet):
    rules = load_detection_rules()

    detect_unknown_mac(packet, rules)
    detect_deauth_flood(packet, rules)
    detect_evil_twin(packet, rules)
    detect_beacon_flood(packet, rules)
    detect_probe_request(packet, rules)
