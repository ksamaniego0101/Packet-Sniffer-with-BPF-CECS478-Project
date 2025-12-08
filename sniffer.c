//this is the packet sniffer bpf

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h> // Added for UDP support
#include <time.h>
#include <string.h>

FILE* logfile = NULL;

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_dumper_t* dumper = (pcap_dumper_t*)args;

    // 1. saves filtered packet to pcap
    if (dumper) {
        pcap_dump((u_char*)dumper, header, packet);
        pcap_dump_flush(dumper);
    }

    struct ip* ip_hdr = (struct ip*)(packet + 14);
    if (ip_hdr->ip_v != 4) return;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // logs to file
    if (logfile) {
        fprintf(logfile, "%ld: %s -> %s (Len: %d)\n",
            header->ts.tv_sec, src_ip, dst_ip, header->len);
        fflush(logfile);
    }
}

int main(int argc, char* argv[]) {
    // Usage: ./sniffer <interface> <filter> <log_prefix>
    if (argc < 4) {
        printf("Usage: %s <iface> <filter> <log_prefix>\n", argv[0]);
        return 1;
    }

    char* dev = argv[1];
    char* filter_exp = argv[2];
    char* prefix = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];

    // constructs the different file names
    char log_name[64];
    char pcap_name[64];
    snprintf(log_name, sizeof(log_name), "%s.log", prefix);
    snprintf(pcap_name, sizeof(pcap_name), "%s.pcap", prefix);

    logfile = fopen(log_name, "w");
    if (!logfile) { perror("Log file error"); return 1; }

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) { fprintf(stderr, "Error: %s\n", errbuf); return 1; }

    pcap_dumper_t* dumper = pcap_dump_open(handle, pcap_name);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 2;
    }
    pcap_setfilter(handle, &fp);

    printf("Sniffer running. Filter: '%s' | Output: %s\n", filter_exp, log_name);

    // captures 4 packets then exits
    pcap_loop(handle, 4, packet_handler, (u_char*)dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);
    fclose(logfile);
    return 0;
}