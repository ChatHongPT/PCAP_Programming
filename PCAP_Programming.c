/* C,C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램 */
#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP header */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4; /* IP header length and version */
    unsigned char iph_tos;              /* Type of service */
    unsigned short iph_len;             /* IP Packet length (data + header) */
    unsigned short iph_ident;           /* Identification */
    unsigned short iph_flag:3, iph_offset:13; /* Fragmentation flags and offset */
    unsigned char iph_ttl;              /* Time to Live */
    unsigned char iph_protocol;         /* Protocol type */
    unsigned short iph_chksum;          /* IP datagram checksum */
    struct in_addr iph_sourceip;        /* Source IP address */
    struct in_addr iph_destip;          /* Destination IP address */
};

/* TCP header */
struct tcpheader {
    u_short tcp_sport;     /* source port */
    u_short tcp_dport;     /* destination port */
    u_int tcp_seq;         /* sequence number */
    u_int tcp_ack;         /* acknowledgement number */
    u_char tcp_offx2;      /* data offset, rsvd */
    u_char tcp_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;       /* window */
    u_short tcp_sum;       /* checksum */
    u_short tcp_urp;       /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

    // Print Ethernet information
    printf("MAC Source Address: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("MAC Destination Address: %s\n\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // Print IP information
    printf("IP Source Address: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("IP Destination Address: %s\n\n", inet_ntoa(ip->iph_destip));

    // Print TCP PORT information
    printf("Port Source Address: %d\n", ntohs(tcp->tcp_sport));
    printf("Port Destination Address: %d\n\n", ntohs(tcp->tcp_dport));
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("<Capture the Packet!>\n");

    // Open live pcap session on NIC with name ens33
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    // Capture packets and process them
    pcap_loop(handle, 10, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
