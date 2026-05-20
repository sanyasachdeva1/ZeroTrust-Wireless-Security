import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent / "src"))

from scapy.all import RadioTap, Dot11, Dot11Deauth
from attack_detector import analyze_packet


def run_simulation():
    print("[*] Running Zero Trust Wireless Security Lab simulation...")

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

    analyze_packet(packet)

    print("[*] Simulation complete. Check logs/alerts.log")


if __name__ == "__main__":
    run_simulation()
