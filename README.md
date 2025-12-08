# Packet-Sniffer-with-BPF-CECS478-Project
Packet Sniffer Project with BPF for CECS478

# Problem Statement
There are many modern networks that produce  a large amount of packet streams and being able to detect the traffic that is relevant can be difficult. Sniffers that capture everything can be impractical and would not be ideal for continuous, lightweight monitoring. With this project, I will try to build a C-based packet sniffer that is able to leverage the kernel-level Berkeley Packet Filter (BPF) to be able to perform efficient, early packet filtering and be able to identify specific packets that need to be analyzed so that you are able to identify anything that could be problematic, or there is data you are interested in. My main objective is to try and show how kernel filtering can lower overhead and enable real-time monitoring. I want to be able to showcase how a packet sniffer can efficiently filter specific items with tools we have been using in this class.

# Project Summary 
I want to be able to demonstrate how kernel-level filtering with BPF enables eficient and targeted packet campture for real time security analysis.

# Architecture
**Vertical Slice:** 'Ingest -> Filter -> Log -> Export'
1. **Ingest:** We use 'libcap' so that we are able to attach to a network interface.
2. **Filter:** We have the BPF bytecode that  is able to filter traffic at the kernel level. This is done by typing what type of filter to sniff out (e.g, "icmp or tcp")
3. **Log:** We have the metadata (IPs, Ports, Length) written to text logs and also a csv file for observability, so that it is easier to look at and show what has been taken down.
4. **Export:** Raw packets containing the information for the captured packets are dumped to '.pcap' files to be analyzed in Wireshark to make sure the right traffic is being filtered and captured.

# Runbook (How to Run)
**Prerequisites:** I ended up using Linux/Wsl with 'gcc', 'make', and 'libpcap-dev'. This is need to be able to run the make file that runs the tests and prints out the results for the user. I was not able to use a docker container for this project, so I hope that the makefile and commands run smoothly on your device with the aforementioned prequisites to run this packet sniffer.

**Command Sequence:** To be able to build the system, run tets, and gereate the evidence: make clean && make demo && make report (subject to change)
