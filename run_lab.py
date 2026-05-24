import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent / "src"))

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt
from attack_detector import analyze_packet


def simulate_deauth_flood():
    attacker_mac = "AA:BB:CC:DD:EE:01"
    victim_mac = "AA:BB:CC:DD:EE:02"

    print("[*] Simulating deauthentication flood...")

    for _ in range(5):
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


def simulate_unknown_mac():
    unknown_mac = "DE:AD:BE:EF:00:01"

    print("[*] Simulating unknown wireless device...")

    packet = (
        RadioTap()
        / Dot11(
            type=2,
            subtype=0,
            addr1="AA:BB:CC:DD:EE:02",
            addr2=unknown_mac,
            addr3="AA:BB:CC:DD:EE:99",
        )
    )

    analyze_packet(packet)


def simulate_evil_twin():
    print("[*] Simulating evil twin access point...")

    packet = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="11:22:33:44:55:66",
            addr3="11:22:33:44:55:66",
        )
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info="Cisco-Corp-WiFi")
    )

    analyze_packet(packet)


def simulate_beacon_flood():
    print("[*] Simulating beacon flood...")

    for _ in range(10):
        packet = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="22:33:44:55:66:77",
                addr3="22:33:44:55:66:77",
            )
            / Dot11Beacon()
            / Dot11Elt(ID="SSID", info="Flooded-Network")
        )

        analyze_packet(packet)


def run_simulation():
    print("[*] Running Wireless Zero Trust Detection & Response simulation...")

    simulate_deauth_flood()
    simulate_unknown_mac()
    simulate_evil_twin()
    simulate_beacon_flood()

    log_dir = Path(os.environ.get("ZT_LOG_DIR", "logs"))

    print("[*] Simulation complete.")
    print(f"[*] Review SOC logs: {log_dir / 'alerts.log'}")
    print(f"[*] Review JSON alerts: {log_dir / 'alerts.jsonl'}")


if __name__ == "__main__":
    run_simulation()
