import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from scapy.all import rdpcap
from attack_detector import analyze_packet


def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    print(f"[*] Loaded {len(packets)} packets from {pcap_file}")

    for packet in packets:
        analyze_packet(packet)

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

    args = parser.parse_args()
    analyze_pcap(args.pcap)


if __name__ == "__main__":
    main()
