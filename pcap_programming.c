#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // Ethernet Header에서 소스 MAC/대상 MAC 주소 추출
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

        if (ip->iph_protocol == IPPROTO_TCP) { // Check if it's TCP
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            printf("==Ethernet Header==\n");
            printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], 
            eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], 
            eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("==IP Header==\n");
            printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("==TCP Header==\n");
            printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // Message
            int data_offset = sizeof(struct ethheader) + sizeof(struct ipheader) + (TH_OFF(tcp) * 4);
            int data_length = pkthdr->len - data_offset;
            if (data_length > 0) {
                printf("Message[30byte]: ");
                for (int i = 0; i < data_length && i < 30; i++) {
                    printf("%02X ", packet[data_offset + i]);
                }
                printf("\n\n");
            }
        }
    }
}

int main() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류 버퍼
    pcap_t *handle; // PCAP 핸들러

    // 네트워크 디바이스 찾기
    pcap_if_t *alldevs, *dev_list;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("네트워크 디바이스 목록을 찾을 수 없음: %s\n", errbuf);
        return 1;
    }

    // 첫 번째 네트워크 디바이스 선택
    dev = alldevs->name;

    // 네트워크 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("네트워크 디바이스를 열 수 없음: %s\n", errbuf);
        return 1;
    }

    // 패킷 스니핑 루프 시작
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
