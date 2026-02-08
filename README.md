# Zero Trust Wireless Security Engine
A Python-based security framework that implements Zero Trust principles at the wireless link layer.

## Features
- **Real-time IDS:** Detects 802.11 de-authentication floods and rogue AP behaviors using Scapy.
- **Dynamic Trust Scoring:** Evaluates device MAC addresses against an authorized whitelist.
- **Automated Logging:** Outputs threat data in CSV format, ready for Grafana/ELK ingestion.

## Tech Stack
- **Language:** Python 3.x
- **Libraries:** Scapy, Pandas
- **Environment:** Kali Linux / Monitor Mode NIC

## How to Run
1. Enable monitor mode: `sudo airmon-ng start wlan0`
2. Run the engine: `sudo python3 engine.py`
