from scapy.all import *
import logging
from datetime import datetime

# Setup logging for Grafana/Dashboard integration
logging.basicConfig(filename='threat_log.csv', level=logging.INFO, 
                    format='%(asctime)s,%(message)s')

class ZeroTrustEngine:
    def __init__(self):
        self.authorized_macs = ["00:11:22:33:44:55"] # Add your known device MACs
        print("[*] Zero Trust Engine Started. Monitoring Wireless Perimeter...")

    def packet_callback(self, pkt):
        # 1. Detect De-authentication Attacks (IDS Feature)
        if pkt.haslayer(Dot11Deauth):
            addr1 = pkt.addr1  # Receiver
            addr2 = pkt.addr2  # Sender (usually AP)
            reason = pkt.getlayer(Dot11Deauth).reason
            msg = f"DEAUTH_DETECTED,Target:{addr1},Source:{addr2},Reason:{reason},TrustScore:0"
            print(f"[!] ALERT: {msg}")
            logging.info(msg)

        # 2. Identify Unauthorized Devices (Zero Trust Feature)
        elif pkt.haslayer(Dot11):
            source_mac = pkt.addr2
            if source_mac and source_mac not in self.authorized_macs:
                # Assign low trust score to unknown devices
                msg = f"UNAUTHORIZED_DEVICE,MAC:{source_mac},Action:Flagged,TrustScore:20"
                logging.info(msg)

# Start sniffing (requires Monitor Mode: sudo airmon-ng start wlan0)
engine = ZeroTrustEngine()
sniff(iface="wlan0mon", prn=engine.packet_callback, store=0)
