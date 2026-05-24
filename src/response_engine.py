from logger import log_alert


def isolate_device(mac):
    """
    Simulate isolating a compromised wireless device.

    In a real enterprise environment, this could map to:
    - Cisco ISE / NAC quarantine
    - Firewall deny rule
    - Wireless controller client block
    - Identity/session revocation
    """

    print(f"[!] Simulated NAC quarantine triggered for device: {mac}")
    print(f"[!] Simulated firewall block triggered for device: {mac}")

    log_alert(
        threat="Device Isolation Triggered",
        mac=mac,
        severity="CRITICAL",
        action="Simulated NAC quarantine and firewall block",
        details={
            "response_type": "containment",
            "nac_action": "quarantine",
            "firewall_action": "block_mac",
            "status": "simulated"
        }
    )
