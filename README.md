# Wireless Zero Trust Detection & Response Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Python Security Lab Check](https://github.com/sanyasachdeva1/ZeroTrust-Wireless-Security/actions/workflows/python-check.yml/badge.svg)](https://github.com/sanyasachdeva1/ZeroTrust-Wireless-Security/actions/workflows/python-check.yml)

A defensive wireless security lab for detecting suspicious 802.11 Wi-Fi activity using Python, Scapy, configurable detection rules, and Zero Trust response logic.
The project uses safe in-memory packet simulations. It does not transmit attack traffic.

## Why I Built This

I built this lab to connect enterprise wireless security concepts with blue-team detection engineering. The goal was to simulate how suspicious 802.11 activity can be detected, scored, logged, and mapped to a Zero Trust response workflow without transmitting real attack traffic.

## What It Detects

- Deauthentication floods
- Unknown wireless devices
- Possible evil twin access points
- Beacon floods
- Probe requests
- Risk-scored alerts and guarded simulated isolation

## How It Works

1. Simulated packets or offline PCAP packets are sent to the detector.
2. Detection rules are loaded from `config/detection_rules.json`.
3. Trusted devices and SSID/BSSID expectations are loaded from `config/trusted_devices.json`.
4. Alerts are written to `logs/alerts.log` and `logs/alerts.jsonl`.
5. Suspicious trusted devices lose trust score.
6. If risk and trust thresholds allow it, simulated containment is logged.

## Architecture

```mermaid
flowchart LR
    A[Simulated Scapy Packets / Optional PCAP] --> B[Attack Detector]
    B --> C[Detection Rules]
    C --> D[SOC-style Alerts]
    C --> E[Zero Trust Trust Engine]
    E --> F[Trust Score Update]
    F --> G{Risk + Trust Threshold Met?}
    G -->|Yes| H[Guarded Simulated Isolation]
    G -->|No| I[Log and Continue]
    H --> J[logs/alerts.log]
    D --> J
    J --> K[logs/alerts.jsonl]
```

## Run The Lab

```bash
pip install -r requirements.txt
python3 run_lab.py
```

View alerts:

```bash
cat logs/alerts.log
cat logs/alerts.jsonl
```

## Optional PCAP Analysis

```bash
python3 src/pcap_analyzer.py --pcap path/to/wireless_capture.pcap
```

Try the small included sample:

```bash
python3 src/pcap_analyzer.py --pcap sample-data/wireless_lab_sample.pcap
```

The analyzer also handles non-wireless PCAPs and reports when no 802.11 frames are present. Only analyze captures you are authorized to use.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Configuration

Detection thresholds, severities, and cooldowns live in:

```text
config/detection_rules.json
```

Trusted devices, trusted SSID/BSSID expectations, trust penalties, and response safety controls live in:

```text
config/trusted_devices.json
```

## Real-World Mapping

In a production wireless environment, this type of workflow could map to:

- Wireless LAN Controller telemetry for client and AP behavior
- Cisco ISE or NAC policy for identity-aware quarantine
- SIEM ingestion for SOC monitoring and correlation
- SOAR workflows for response approval and containment
- RF analysis tools for validating wireless interference or rogue AP activity

## Notes

This is a lab project, not a production wireless IDS. MAC addresses can be spoofed, thresholds need tuning, and real deployments should combine this kind of logic with controller telemetry, NAC identity, SIEM correlation, and RF context.

## Safety

This project is for educational and defensive use only. Test only on systems and networks you own or have permission to assess.
