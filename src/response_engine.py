from logger import log_alert

def isolate_device(mac):
    """
    Simulate isolating a compromised wireless device.
    In a real environment this could trigger:
    - NAC quarantine
    - Firewall rule updates
    - Identity revocation
    """
    print(f"[!] Isolating device with MAC: {mac}")

    log_alert(
        threat="Device Isolation Triggered",
        mac=mac,
        action="Wireless Access Revoked"
    )

