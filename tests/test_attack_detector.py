import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import RadioTap, Dot11, Dot11Deauth
from attack_detector import analyze_packet


def test_deauth_flood_generates_alert():
    for _ in range(7):
        packet = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1="AA:BB:CC:DD:EE:02",
                addr2="AA:BB:CC:DD:EE:01",
                addr3="AA:BB:CC:DD:EE:01",
            )
            / Dot11Deauth(reason=7)
        )

        analyze_packet(packet)

    log_content = Path(os.environ["ZT_LOG_DIR"], "alerts.log").read_text()

    assert "Wireless Deauthentication Flood" in log_content
    assert log_content.count("Wireless Deauthentication Flood") == 1
