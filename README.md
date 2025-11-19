# Packet-Sniffer-with-BPF-CECS478-Project
Packet Sniffer Project with BPF for CECS478

# Problem Statement
There are many modern networks that produce  a large amount of packet streams and being able to detect the traffic that is relevant can be difficult. Sniffers that capture everything can be impractical and would not be ideal for continuous, lightweight monitoring. With this project, I will try to build a C-based packet sniffer that is able to leverage the kernel-level Berkeley Packet Filter (BPF) to be able to perform efficient, early packet filtering and be able to identify specific packets that need to be analyzed so that you are able to identify anything that could be problematic, or there is data you are interested in. My main objective is to try and show how kernel filtering can lower overhead and enable real-time monitoring. I want to be able to showcase how a packet sniffer can efficiently filter specific items with tools we have been using in this class.

#
