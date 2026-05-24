# Sample PCAPs

Use this directory for small, authorized packet captures.

Wireless detections require 802.11 frames. Regular Ethernet/TCP/UDP captures can still be parsed by `src/pcap_analyzer.py`, but they will report `0` wireless packets and should not trigger wireless detections.
