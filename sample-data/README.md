# Sample PCAPs

This directory contains a tiny synthetic wireless sample capture for offline analyzer testing.

```bash
python3 src/pcap_analyzer.py --pcap sample-data/wireless_lab_sample.pcap
```

Wireless detections require 802.11 frames. Regular Ethernet/TCP/UDP captures can still be parsed by `src/pcap_analyzer.py`, but they will report `0` wireless packets and should not trigger wireless detections.
