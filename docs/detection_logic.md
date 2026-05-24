# Detection Logic

The lab uses simple, configurable detection rules. Thresholds, severities, and cooldowns are stored in `config/detection_rules.json`.

| Detection | Signal | Default Rule | Notes |
|---|---|---|---|
| Deauth flood | Repeated deauth frames from one source MAC | 5 events in 60 seconds | Reduces trust score and can trigger simulated isolation |
| Unknown MAC | Source MAC not in trusted inventory | Immediate | Cooldown prevents duplicate alert bursts |
| Evil twin | Trusted SSID with suspicious AP attributes | Immediate | Checks BSSID and optional channel/security expectations |
| Beacon flood | Repeated beacon frames from one BSSID | 10 events in 60 seconds | Cooldown prevents repeated alerts after threshold |
| Probe request | Probe request frame observed | Immediate | Low severity visibility signal |

## Tuning

Use `config/detection_rules.json` to adjust:

- `threshold`
- `window_seconds`
- `cooldown_seconds`
- `severity`
- `enabled`
- `min_indicators` for evil twin detection

Use `config/trusted_devices.json` to adjust:

- trusted device MACs
- trusted SSID/BSSID mappings
- expected channel and security for trusted SSIDs
- trust score threshold
- trust penalty
- response mode and isolation risk threshold

## Limitations

This is a lab detector. MAC addresses can be spoofed, thresholds can miss slow attacks, and real environments should combine packet logic with wireless controller telemetry, NAC identity, SIEM correlation, and RF context.
