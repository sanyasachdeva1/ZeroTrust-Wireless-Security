from logger import log_alert


def isolate_device(mac):
    """
    Simulate isolating a compromised wireless device.

    In a real enterprise environment, this could trigger:
    - NAC quarantine
    - Cisco ISE policy update
    - Firewall rule update
    - Identity/session revocation
    """

    print(f"[!] Simulated isolation triggered for device: {mac}")

    log_alert(
        threat="Device Isolation Triggered",
        mac=mac,
        action="Wireless access revoked / NAC quarantine simulated",
        severity="CRITICAL"
    )
