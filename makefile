CC = gcc
CFLAGS = -Wall
LIBS = -lpcap

all: sniffer

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o sniffer sniffer.c $(LIBS)

# --- THE MAIN DEMO SUITE ---
demo: sniffer
	# 1. Cleanup old files
	sudo rm -f *.log *.pcap
	@echo "Requesting sudo permissions..."
	@sudo true

	# ==========================================
	# TEST 1: The Happy Path (ICMP)
	# ==========================================
	@echo "\n[TEST 1] Running ICMP Sniffer..."
	# Run sniffer in background
	sudo ./sniffer eth0 "icmp" test_icmp > /dev/null 2>&1 & 
	sleep 1
	# Generate traffic
	ping -c 4 8.8.8.8 > /dev/null
	@echo ">> ICMP Test Complete."

	# ==========================================
	# TEST 2: The Negative Test (Ignore Noise)
	# ==========================================
	@echo "\n[TEST 2] Running TCP Sniffer (Should IGNORE pings)..."
	# Run sniffer looking for fake port
	sudo timeout 3 ./sniffer eth0 "tcp port 9999" test_negative > /dev/null 2>&1 || true
	@echo ">> Negative Test Complete."
	# Check if it failed correctly
	@if [ -s test_negative.log ]; then \
		echo "FAILED: Sniffer captured packets it should have ignored!"; \
	else \
		echo "PASSED: Sniffer correctly ignored unrelated traffic."; \
	fi

	# ==========================================
	# TEST 3: Ground Truth (Raw vs Filtered)
	# ==========================================
	@echo "\n[TEST 3] Running Full Capture Comparison..."
	# -Z root fixes the "0 byte file" permission error
	sudo timeout 5 tcpdump -i eth0 -w all_traffic.pcap -Z root > /dev/null 2>&1 &
	
	# Start our sniffer (ICMP only)
	sudo ./sniffer eth0 "icmp" test_filtered > /dev/null 2>&1 &
	
	sleep 1
	ping -c 4 8.8.8.8 > /dev/null
	
	@echo ">> Comparison Test Complete."
	@echo "Files generated:"
	@ls -lh all_traffic.pcap test_filtered.pcap

	# ==========================================
	# FINAL CLEANUP (Fixes Frozen Terminal)
	# ==========================================
	@stty sane

report:
	@echo "\n--- FINAL REPORT ---"
	@echo "1. ICMP Log Content (First 3 lines):"
	@head -n 3 test_icmp.log
	@echo "\n2. File Sizes (Proof of Filtering):"
	@ls -lh all_traffic.pcap test_filtered.pcap

clean:
	rm -f sniffer *.log *.pcap
