import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from attack_detector import analyze_packet


def test_evil_twin_generates_alert():
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

    log_content = Path(os.environ["ZT_LOG_DIR"], "alerts.log").read_text()

    assert "Possible Evil Twin Access Point" in log_content


def test_trusted_bssid_does_not_generate_evil_twin_alert():
    packet = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="AA:BB:CC:DD:EE:99",
            addr3="AA:BB:CC:DD:EE:99",
        )
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info="Cisco-Corp-WiFi")
    )

    analyze_packet(packet)

    log_file = Path(os.environ["ZT_LOG_DIR"], "alerts.log")
    log_content = log_file.read_text() if log_file.exists() else ""

    assert "Possible Evil Twin Access Point" not in log_content
