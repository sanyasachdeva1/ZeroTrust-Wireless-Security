from scapy.all import sniff, Dot11
from attack_detector import analyze_packet

def process_packet(packet):
    if packet.haslayer(Dot11):
        analyze_packet(packet)

def start_sniffing(interface="wlan0mon"):
    print(f"[+] Starting wireless packet capture on {interface}")
    sniff(iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()

