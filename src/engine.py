import json
import logging
import os
from scapy.all import *

# 1. Setup Advanced Logging
logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - [RISK: %(levelname)s] - %(message)s'
)

class ZeroTrustWireless:
    def __init__(self, config_path='authorized_devices.json'):
        self.load_config(config_path)
        print(f"[*] Zero Trust Engine Active. Monitoring {len(self.authorized_macs)} devices.")

    def load_config(self, path):
        with open(path, 'r') as f:
            config = json.load(f)
            self.authorized_macs = config['authorized_macs']
            self.auto_block = config['security_settings']['auto_block']

    def block_malicious_actor(self, mac):
        """Simulates an automated SOAR response to isolate a threat."""
        if self.auto_block:
            # On Linux, this would execute a firewall block
            # os.system(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP")
            print(f"[ACTION] Automated Response: MAC {mac} has been blacklisted in Firewall.")
            logging.warning(f"BLOCK_ACTION_TRIGGERED: {mac}")

    def process_packet(self, pkt):
        # Check for De-authentication (DoS) attacks
        if pkt.haslayer(Dot11Deauth):
            source = pkt.addr2
            target = pkt.addr1
            print(f"[!] THREAT: Deauth Flood detected from {source} targeting {target}")
            logging.error(f"DEAUTH_ATTACK: Source={source}, Target={target}")
            self.block_malicious_actor(source)

        # Check for Unauthorized Access (Zero Trust Violation)
        elif pkt.haslayer(Dot11):
            source_mac = pkt.addr2
            if source_mac and source_mac.upper() not in self.authorized_macs:
                if source_mac not in ["ff:ff:ff:ff:ff:ff", None]: # Ignore broadcasts
                    print(f"[?] UNKNOWN DEVICE: {source_mac} is attempting to communicate.")
                    logging.info(f"UNAUTHORIZED_MAC_DETECTED: {source_mac}")
                    # Optional: block unknown devices immediately (Strict Zero Trust)
                    # self.block_malicious_actor(source_mac)

# Start the Engine
if __name__ == "__main__":
    # Ensure you are running as sudo/root for packet capture
    engine = ZeroTrustWireless()
    # Replace 'wlan0mon' with your actual monitor-mode interface
    sniff(iface="wlan0mon", prn=engine.process_packet, store=0)
