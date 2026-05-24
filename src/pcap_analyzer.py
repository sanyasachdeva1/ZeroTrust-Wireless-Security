import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from scapy.all import Dot11, rdpcap
from attack_detector import analyze_packet


def analyze_pcap(pcap_file, max_packets=None):
    packets = rdpcap(pcap_file)
    selected_packets = packets[:max_packets] if max_packets else packets
    wireless_count = 0

    print(f"[*] Loaded {len(packets)} packets from {pcap_file}")
    if max_packets:
        print(f"[*] Analyzing first {len(selected_packets)} packets")

    for packet in selected_packets:
        if packet.haslayer(Dot11):
            wireless_count += 1
        analyze_packet(packet)

    print(f"[*] Wireless 802.11 packets analyzed: {wireless_count}")
    if wireless_count == 0:
        print("[*] No 802.11 frames found. Non-wireless PCAPs are parsed but will not trigger wireless detections.")

    print("[*] PCAP analysis complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file using the Wireless Zero Trust Detection Engine"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to PCAP file"
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        help="Optional packet limit for quick checks"
    )

    args = parser.parse_args()
    analyze_pcap(args.pcap, args.max_packets)


if __name__ == "__main__":
    main()
