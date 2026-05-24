import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import RadioTap, Dot11
from attack_detector import analyze_packet


def test_unknown_mac_generates_alert():
    for _ in range(2):
        packet = (
            RadioTap()
            / Dot11(
                type=2,
                subtype=0,
                addr1="AA:BB:CC:DD:EE:02",
                addr2="DE:AD:BE:EF:00:01",
                addr3="AA:BB:CC:DD:EE:99",
            )
        )

        analyze_packet(packet)

    log_content = Path(os.environ["ZT_LOG_DIR"], "alerts.log").read_text()

    assert "Unknown Wireless Device" in log_content
    assert log_content.count("Unknown Wireless Device") == 1
