CC = gcc
CFLAGS = -Wall
LIBS = -lpcap

all: sniffer

sniffer: sniffer.c
	$(CC) $(CFLAGS) -o sniffer sniffer.c $(LIBS)


up: sniffer
	# Simulating container build/setup
	mkdir -p artifacts/release
	@echo "System Built and Directory is prepared."

demo: sniffer
	@echo "Requesting sudo permissions..."
	@sudo true

	# PHASE 1: Start Master Recorder (Background)
	@echo "\n[PHASE 1] Recording full session (tcpdump)..."
	sudo tcpdump -i eth0 -w artifacts/release/full_session.pcap -Z root > /dev/null 2>&1 &
	sleep 2

	# PHASE 2: Individual Protocol Tests
	@echo "\n[PHASE 2] Testing Each Individual Protocol..."
	
	# Test A: ICMP
	sudo ./sniffer eth0 "icmp" artifacts/release/icmp_test 8 > /dev/null 2>&1 & 
	sleep 1
	ping -c 4 8.8.8.8 > /dev/null

	# Test B: UDP
	sudo ./sniffer eth0 "udp" artifacts/release/udp_test 8 > /dev/null 2>&1 &
	sleep 1
	dig @8.8.8.8 google.com > /dev/null

	# Test C: TCP
	sudo ./sniffer eth0 "tcp" artifacts/release/tcp_test 12 > /dev/null 2>&1 &
	sleep 1
	curl -I http://google.com > /dev/null 2>&1 || wget -q --spider http://google.com

	# PHASE 3: Negative Test (Should capture nothing)
	@echo "\n[PHASE 3] Negative Test (checking to make sure nothing is captured)..."
	sudo timeout 3 ./sniffer eth0 "tcp port 9999" artifacts/release/negative_test 4 > /dev/null 2>&1 || true
	# Generate noise to prove it is ignored
	ping -c 2 8.8.8.8 > /dev/null &
	dig @8.8.8.8 google.com > /dev/null &
	sleep 3

	# PHASE 4: Mixed Traffic Test (multiple filters)
	@echo "\n[PHASE 4] Mixed Traffic Sample..."
	sudo timeout 10 ./sniffer eth0 "ip" artifacts/release/mixed_capture 16 > /dev/null 2>&1 &
	# Generate all traffic
	dig @8.8.8.8 amazon.com > /dev/null 2>&1 &
	ping -c 5 8.8.8.8 > /dev/null 2>&1 & 
	curl -I http://google.com > /dev/null 2>&1 &
	sleep 7

	# PHASE 5: Cleanup & Finalize
	@echo "\n[PHASE 5] Cleaning up..."
	

	@echo "\n>>> DEMO COMPLETE <<<"
	@ls -l artifacts/release/
	@stty sane


clean:
	rm -f sniffer *.log *.pcap *.csv
	rm -rf artifacts
