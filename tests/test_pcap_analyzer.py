import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from scapy.all import Ether, IP, TCP, wrpcap

from pcap_analyzer import analyze_pcap


def test_non_wireless_pcap_reports_zero_dot11_packets(tmp_path, capsys):
    pcap_file = tmp_path / "tcp_sample.pcap"
    packet = Ether() / IP(dst="192.0.2.10") / TCP(dport=443)

    wrpcap(str(pcap_file), [packet])
    analyze_pcap(str(pcap_file))

    output = capsys.readouterr().out

    assert "Wireless 802.11 packets analyzed: 0" in output
    assert "No 802.11 frames found" in output


def test_included_wireless_sample_has_dot11_packets(capsys):
    sample = Path(__file__).resolve().parents[1] / "sample-data" / "wireless_lab_sample.pcap"

    analyze_pcap(str(sample))

    output = capsys.readouterr().out

    assert "Wireless 802.11 packets analyzed: 7" in output
    assert "Possible Evil Twin Access Point" in output
    assert "Wireless Deauthentication Flood" in output
