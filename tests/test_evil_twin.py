import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from attack_detector import analyze_packet


def test_evil_twin_generates_alert():
    Path("logs").mkdir(exist_ok=True)
    Path("logs/alerts.log").write_text("")
    Path("logs/alerts.jsonl").write_text("")

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

    log_content = Path("logs/alerts.log").read_text()

    assert "Possible Evil Twin Access Point" in log_content
