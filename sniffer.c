//this is the packet sniffer bpf

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <string.h>

FILE* logfile = NULL;

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    pcap_dumper_t* dumper = (pcap_dumper_t*)args;

    // allows to be saved to pcap file
    if (dumper) {
        pcap_dump((u_char*)dumper, header, packet);
        pcap_dump_flush(dumper); // saves to pcap file
    }

    // IP header and skips the first 14 bytes
    struct ip* ip_hdr = (struct ip*)(packet + 14);
    if (ip_hdr->ip_v != 4) return;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // this is used to help detect the protocol that is being used/detected
    char proto_str[10];
    int src_port = 0, dst_port = 0;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        strcpy(proto_str, "TCP");
        struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + (ip_hdr->ip_hl * 4));
        src_port = ntohs(tcp_hdr->source);
        dst_port = ntohs(tcp_hdr->dest);
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        strcpy(proto_str, "UDP");
        struct udphdr* udp_hdr = (struct udphdr*)(packet + 14 + (ip_hdr->ip_hl * 4));
        src_port = ntohs(udp_hdr->source);
        dst_port = ntohs(udp_hdr->dest);
    }
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        strcpy(proto_str, "ICMP");
    }
    else {
        strcpy(proto_str, "OTHER");
    }

    //logs to a seperate file
    if (logfile) {
        // timestamp: protocol /source/destination
        fprintf(logfile, "%ld: [%s] %s:%d -> %s:%d (Len: %d)\n",
            header->ts.tv_sec, proto_str, src_ip, src_port, dst_ip, dst_port, header->len);
        fflush(logfile);
    }
}

int main(int argc, char* argv[]) {
    // correct usage: ./sniffer <iface> <filter> <log_prefix> <count> - so that it shows what you are using where to log to and how many packets
    if (argc < 5) {
        printf("Correct useage: %s <iface> <filter> <log_prefix> <count>\n", argv[0]);
        printf("Keep in mind: <count> of 0 means loop indefinitely.\n");
        return 1;
    }

    char* dev = argv[1];
    char* filter_exp = argv[2];
    char* prefix = argv[3];
    int packet_count = atoi(argv[4]); // string argument converted to integer for the number of packets to be used
    char errbuf[PCAP_ERRBUF_SIZE];

    // file names are constructed here
    char log_name[64];
    char pcap_name[64];
    snprintf(log_name, sizeof(log_name), "%s.log", prefix);
    snprintf(pcap_name, sizeof(pcap_name), "%s.pcap", prefix);

    logfile = fopen(log_name, "w");
    if (!logfile) { perror("Log file error"); return 1; }

    // Open Handle (Promiscuous Mode = 1)
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) { fprintf(stderr, "Error: %s\n", errbuf); return 1; }

    pcap_dumper_t* dumper = pcap_dump_open(handle, pcap_name);

    //bpf filter that translates the to text into bpf bytecode to be read
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 2;
    }
    pcap_setfilter(handle, &fp); //os filters the packet by injecting code into the terminal

    printf("Packet nniffer running. Filter: '%s' | Count: %d\n", filter_exp, packet_count);

    // waits for a packet and passes the function as many times as needed or written with packet count
    pcap_loop(handle, packet_count, packet_handler, (u_char*)dumper);

    // cleanup/shutdown
    pcap_dump_close(dumper);
    pcap_close(handle);
    fclose(logfile);
    return 0;
}