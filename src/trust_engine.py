import json
from response_engine import isolate_device

TRUST_THRESHOLD = 50
TRUST_PENALTY = 30

def evaluate_trust(mac):
    with open("config/trusted_devices.json", "r") as f:
        data = json.load(f)

    for device in data["trusted_devices"]:
        if device["mac"] == mac:
            device["trust_score"] -= TRUST_PENALTY

            print(
                f"[!] Trust score reduced for {mac}. "
                f"Current score: {device['trust_score']}"
            )

            if device["trust_score"] < TRUST_THRESHOLD:
                isolate_device(mac)

    with open("config/trusted_devices.json", "w") as f:
        json.dump(data, f, indent=2)

