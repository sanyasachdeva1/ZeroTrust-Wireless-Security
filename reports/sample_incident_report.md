# Sample Incident Report: Wireless Deauthentication Flood

## Executive Summary

A simulated wireless deauthentication flood was detected against a managed corporate device. The detection engine observed repeated 802.11 deauthentication frames from a monitored source MAC within a defined time window. The device trust score was reduced according to Zero Trust policy, and simulated containment actions were triggered once the trust score fell below the configured threshold.

## Incident Details

| Field | Value |
|---|---|
| Incident Type | Wireless Deauthentication Flood |
| Severity | High |
| Detection Source | Scapy-based 802.11 packet inspection |
| Affected Device | Corporate-Mobile |
| Source MAC | AA:BB:CC:DD:EE:01 |
| Target MAC | AA:BB:CC:DD:EE:02 |
| Detection Window | 5 events within 60 seconds |
| Response | Simulated NAC quarantine and firewall block |

## Timeline

| Step | Event |
|---|---|
| 1 | Simulated wireless deauthentication frames generated |
| 2 | Detection engine identified deauthentication flood threshold breach |
| 3 | SOC-style alert written to `logs/alerts.log` |
| 4 | Structured JSON alert written to `logs/alerts.jsonl` |
| 5 | Trust score reduced based on policy |
| 6 | Device isolation triggered after trust score fell below threshold |

## Zero Trust Decision

The device violated expected wireless behavior and crossed the configured trust threshold. Based on the Zero Trust policy, the device was treated as untrusted and containment was simulated.

## Recommended Remediation

- Validate wireless controller and AP logs.
- Check for rogue clients or nearby unauthorized access points.
- Enforce 802.11w Protected Management Frames where supported.
- Review Cisco ISE / NAC policy for quarantine workflows.
- Monitor repeated deauthentication activity from the same source MAC.
- Tune detection thresholds to reduce false positives.

## Lessons Learned

This simulation demonstrates how wireless packet inspection, identity-based device inventory, trust scoring, and response automation can work together in a Zero Trust wireless security workflow.
