# Wireless Zero Trust Threat Detection & Response Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

This project implements a Python-based wireless security lab that applies **Zero Trust principles**
to detect, evaluate, and respond to malicious activity in **802.11 (Wi-Fi) networks**.

The system demonstrates how modern enterprise wireless security combines **identity-based trust,
continuous verification, threat detection, and automated incident response**, similar to real-world
SOC and Zero Trust environments.

---

## Key Features

- Real-time 802.11 wireless packet inspection using **Scapy**
- **Identity-first Zero Trust model** with dynamic trust scoring per device
- Detection of **wireless deauthentication attacks**
- Threat detection mapped to the **MITRE ATT&CK framework**
- **Automated SOAR-style incident response** for compromised devices
- **SIEM-compatible security logging** for SOC visibility

---

## Architecture Overview

````md
```mermaid
flowchart LR
    A[Simulated 802.11 Packet] --> B[Attack Detector]
    B --> C[Deauth Detection]
    C --> D[SOC-style Alert Logging]
    C --> E[Zero Trust Evaluation]
    E --> F[Trust Score Reduction]
    F --> G{Below Trust Threshold?}
    G -->|Yes| H[Simulated Device Isolation]
    G -->|No| I[Continue Monitoring]
    H --> J[logs/alerts.log]
    D --> J

---

## MITRE ATT&CK Mapping

| Detection | Tactic / Concept | Why it matters |
|---|---|---|
| 802.11 Deauthentication Attack | Impact / Network Denial of Service concept | Deauth frames can force wireless clients to disconnect and disrupt availability |
| Unknown Wireless Device | Initial Access / Rogue Device concept | Unknown devices violate identity-based trust assumptions |
| Trust Score Degradation | Continuous Verification Failure | Repeated suspicious behavior lowers device trust and can trigger response |

---

## Use Cases

- Enterprise wireless intrusion detection
- Zero Trust enforcement in Wi-Fi networks
- SOC analyst training and blue-team simulations
- Security automation and incident response demonstrations

---

## Technologies Used

- Python
- Scapy
- Zero Trust Architecture
- MITRE ATT&CK Framework
- SIEM / SOC Logging Concepts

---
## Lab Demonstration

The Zero Trust pipeline can be executed locally using a safe Scapy-based simulation.  
The simulation does not transmit real wireless attack traffic. It creates an in-memory 802.11 deauthentication packet and sends it through the detection pipeline.

## Running the Lab

### 1. Clone the repository

```bash
git clone https://github.com/sanyasachdeva1/ZeroTrust-Wireless-Security.git
cd ZeroTrust-Wireless-Security
pip install -r requirements.txt
sudo python3 src/engine.py


## Disclaimer

This project is designed for educational and defensive security purposes only.
Attack simulations are non-destructive and do not transmit real malicious traffic.



