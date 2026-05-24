# Detection Logic

This document explains the detection rules used by the Wireless Zero Trust Detection & Response Lab.

## Detection Summary

| Detection | Signal Used | Threshold | Severity | Response |
|---|---|---|---|---|
| Deauthentication Flood | Repeated 802.11 deauth frames from same MAC | 5 events / 60 seconds | High | Reduce trust score and trigger containment if below threshold |
| Unknown MAC | Source MAC not present in trusted inventory | Immediate | High | Generate Zero Trust violation alert |
| Evil Twin SSID | Trusted SSID observed from untrusted BSSID | Immediate | High | Generate rogue AP alert |
| Beacon Flood | Repeated beacon frames from same BSSID | 10 events / 60 seconds | Medium | Generate wireless DoS alert |
| Probe Request | Probe request frame observed | Immediate | Low | Log wireless discovery activity |

---

## 1. Deauthentication Flood Detection

### Signal
The engine observes 802.11 deauthentication frames.

### Logic
If the same source MAC sends 5 or more deauthentication frames within 60 seconds, the event is treated as a deauthentication flood.

### Why it matters
Deauthentication floods can disrupt wireless availability by forcing clients to disconnect from the network.

### False positives
Possible false positives include:

- Wireless driver instability
- AP roaming behavior
- Lab-generated traffic
- Misconfigured wireless clients

### Tuning notes
The threshold can be tuned in:

```bash
config/detection_rules.json
