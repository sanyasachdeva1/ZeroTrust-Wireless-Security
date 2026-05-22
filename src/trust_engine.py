import json
from pathlib import Path

from response_engine import isolate_device
from logger import log_alert


CONFIG_FILE = Path("config/trusted_devices.json")


def load_config():
    with open(CONFIG_FILE, "r") as file:
        return json.load(file)


def save_config(data):
    with open(CONFIG_FILE, "w") as file:
        json.dump(data, file, indent=2)


def evaluate_trust(mac):
    """
    Reduce trust score for a suspicious device.
    If the device is unknown, log it as a Zero Trust violation.
    If trust score falls below threshold, trigger isolation.
    """

    data = load_config()
    settings = data.get("security_settings", {})

    trust_threshold = settings.get("trust_threshold", 50)
    trust_penalty = settings.get("trust_penalty", 30)
    auto_isolate = settings.get("auto_isolate", True)

    for device in data["trusted_devices"]:
        if device["mac"].upper() == mac.upper():
            device["trust_score"] = max(device["trust_score"] - trust_penalty, 0)

            print(
                f"[!] Trust score reduced for {mac}. "
                f"Current score: {device['trust_score']}"
            )

            log_alert(
                threat="Trust Score Reduced",
                mac=mac,
                action=f"Trust score now {device['trust_score']}",
                severity="MEDIUM"
            )

            if auto_isolate and device["trust_score"] < trust_threshold:
                isolate_device(mac)

            save_config(data)
            return

    log_alert(
        threat="Unknown Wireless Device",
        mac=mac,
        action="Device not found in trusted inventory",
        severity="HIGH"
)
