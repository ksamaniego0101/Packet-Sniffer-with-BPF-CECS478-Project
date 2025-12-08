# Evaluation Results (Draft)

## 1. Functional Correctness
To validate the sniffer, we compared its output against the industry-standard `tcpdump`.
* **Method:** Ran both tools simultaneously while pinging 8.8.8.8.
* **Observation:** The `captured_traffic.pcap` (our tool) contained exactly 8 packets (4 requests, 4 replies). The `raw_comparison.pcap` (`tcpdump`) contained matching timestamps.
* **Conclusion:** The BPF filter implementation is functionally correct.

## 2. Filtering Efficiency (Negative Testing)
* **Test:** Applied filter `tcp port 9999` and generated unrelated ICMP traffic.
* **Result:** Log file size was 0 bytes.
* **Conclusion:** The kernel-level BPF filter successfully drops packets before they reach userspace, preventing false positives.
