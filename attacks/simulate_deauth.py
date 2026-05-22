"""
Safe wireless deauthentication simulation.

This does not transmit packets. It creates an in-memory Scapy packet
and sends it to the detection pipeline for local testing.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import RadioTap, Dot11, Dot11Deauth
from attack_detector import analyze_packet


def simulate_attack():
    attacker_mac = "AA:BB:CC:DD:EE:01"
    victim_mac = "AA:BB:CC:DD:EE:02"

    packet = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=12,
            addr1=victim_mac,
            addr2=attacker_mac,
            addr3=attacker_mac,
        )
        / Dot11Deauth(reason=7)
    )

    print("[*] Simulating wireless deauthentication attack...")
    analyze_packet(packet)
    print("[*] Attack simulation complete. Check logs/alerts.log.")


if __name__ == "__main__":
    simulate_attack()
