import json
import os
from pathlib import Path

from logger import log_alert
from response_engine import isolate_device


DEFAULT_CONFIG_FILE = Path("config/trusted_devices.json")


def config_file():
    return Path(os.environ.get("ZT_TRUST_CONFIG_FILE", DEFAULT_CONFIG_FILE))


def load_config():
    with open(config_file(), "r") as file:
        return json.load(file)


def save_config(data):
    with open(config_file(), "w") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def get_trusted_device(mac):
    data = load_config()

    for device in data.get("trusted_devices", []):
        if device["mac"].upper() == mac.upper():
            return device

    return None


def evaluate_trust(mac, reason="Suspicious wireless activity detected", risk_score=None):
    """
    Reduce trust score for a suspicious device.
    If device is unknown, log it as a Zero Trust violation.
    If score falls below threshold, trigger simulated containment once.
    """

    data = load_config()
    settings = data.get("security_settings", {})

    trust_threshold = settings.get("trust_threshold", 50)
    trust_penalty = settings.get("trust_penalty", 30)
    auto_isolate = settings.get("auto_isolate", True)
    persist_trust_updates = settings.get("persist_trust_updates", True)
    response_mode = settings.get("response_mode", "simulate")
    isolation_min_risk_score = settings.get("isolation_min_risk_score", 80)

    for device in data.get("trusted_devices", []):
        if device["mac"].upper() == mac.upper():
            previous_score = device.get("trust_score", 100)
            new_score = max(previous_score - trust_penalty, 0)
            device["trust_score"] = new_score

            print(
                f"[!] Trust score reduced for {mac}. "
                f"Previous score: {previous_score}, Current score: {new_score}"
            )

            log_alert(
                threat="Trust Score Reduced",
                mac=mac,
                severity="MEDIUM",
                action=f"Trust score changed from {previous_score} to {new_score}",
                risk_score=risk_score,
                confidence="medium",
                details={
                    "previous_score": previous_score,
                    "current_score": new_score,
                    "reason": reason,
                    "threshold": trust_threshold,
                    "response_mode": response_mode,
                }
            )

            should_isolate = (
                auto_isolate
                and response_mode == "simulate"
                and new_score < trust_threshold
                and (risk_score is None or risk_score >= isolation_min_risk_score)
                and not device.get("isolated", False)
            )

            if should_isolate:
                isolate_device(mac)
                device["isolated"] = True

            if persist_trust_updates:
                save_config(data)
            return

    log_alert(
        threat="Unknown Wireless Device",
        mac=mac,
        severity="HIGH",
        action="Device not found in trusted inventory",
        risk_score=risk_score,
        confidence="medium",
        details={
            "reason": "MAC address not present in trusted device inventory",
            "zero_trust_decision": "deny_or_quarantine"
        }
    )
