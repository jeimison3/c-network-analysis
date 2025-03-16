#include <stdio.h>
#ifndef __USE_MISC
    #define __USE_MISC
#endif
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <string.h>


void intercept_packet_tcp(struct tcphdr *tcp) {
    printf("[TCP] [%c%c%c%c%c%c] :%u -> :%u\n", tcp->syn?'S':'.', tcp->ack?'A':'.', tcp->psh?'P':'.', tcp->rst?'R':'.', tcp->fin?'F':'.', tcp->urg?'U':'.', ntohs(tcp->source), ntohs(tcp->dest));
}

void intercept_packet_udp(struct udphdr *udp) {
    printf("[UDP] :%u -> :%u LEN=%u\n", ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
}

void intercept_packet_icmp(struct icmphdr *icmp) {
    printf("[ICMP] SEQ=%u\n", ntohs(icmp->un.echo.sequence));
}

void intercept_packet_icmpv6(struct icmp6hdr *icmp) {
    printf("[ICMPv6] SEQ=%u\n", ntohs(icmp->icmp6_sequence));
}

void intercept_packet_ip(struct ether_header *eth_header, struct pcap_pkthdr packet_header) {
    struct iphdr *ip = (void*)eth_header + sizeof(struct ether_header);
    printf("[IP] %u.%u.%u.%u -> %u.%u.%u.%u\n", ip->saddr&0xFF, (ip->saddr>>8)&0xFF, (ip->saddr>>16)&0xFF, (ip->saddr>>24)&0xFF,  ip->daddr&0xFF, (ip->daddr>>8)&0xFF, (ip->daddr>>16)&0xFF, (ip->daddr>>24)&0xFF);
    if(ip->protocol == IPPROTO_TCP){
        printf("Pacote L4: TCP\n");
        struct tcphdr *tcp = (void*)ip + sizeof(struct iphdr);
        intercept_packet_tcp(tcp);
    } else if(ip->protocol == IPPROTO_UDP){
        printf("Pacote L4: UDP\n");
        struct udphdr *udp = (void*)ip + sizeof(struct iphdr);
        intercept_packet_udp(udp);
    } else if(ip->protocol == IPPROTO_ICMP){
        printf("Pacote L4: ICMP\n");
        struct icmphdr *icmp = (void*)ip + sizeof(struct iphdr);
        intercept_packet_icmp(icmp);
    } else
        printf("Pacote L4: 0x%02X (%u)\n", ip->protocol, ip->protocol);
}

void intercept_packet_ipv6(struct ether_header *eth_header, struct pcap_pkthdr packet_header) {
    struct ipv6hdr *ip = (void*)eth_header + sizeof(struct ether_header);
    printf("[IPv6] ");
    __u8 zeroed = 0;
    for(__u8 p = 0; p < 8; p++){
        if(ip->saddr.__in6_u.__u6_addr16[p]){
            printf("%s%04x", p>0?":":"",ntohs(ip->saddr.__in6_u.__u6_addr16[p]));
            zeroed = 0;
        } else {
            if(!zeroed){
                printf(":");
                zeroed = 1;
            }
        }
    }
    printf(" -> ");
    zeroed = 0;
    for(__u8 p = 0; p < 8; p++){
        if(ip->daddr.__in6_u.__u6_addr16[p]){
            printf("%s%04x", p>0?":":"",ntohs(ip->daddr.__in6_u.__u6_addr16[p]));
            zeroed = 0;
        } else {
            if(!zeroed){
                printf(":");
                zeroed = 1;
            }
        }
    }
    printf("\n");
    if(ip->nexthdr == IPPROTO_TCP){
        printf("Pacote L4: TCP\n");
        struct tcphdr *tcp = (void*)ip + sizeof(struct ipv6hdr);
        intercept_packet_tcp(tcp);
    } else if(ip->nexthdr == IPPROTO_UDP){
        printf("Pacote L4: UDP\n");
        struct udphdr *udp = (void*)ip + sizeof(struct iphdr);
        intercept_packet_udp(udp);
    } else if(ip->nexthdr == IPPROTO_ICMPV6){
        printf("Pacote L4: ICMPv6\n");
        struct icmp6hdr *icmp = (void*)ip + sizeof(struct iphdr);
        intercept_packet_icmpv6(icmp);
    } else
        printf("Pacote L4: 0x%02X (%u)\n", ip->nexthdr, ip->nexthdr);
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("============\n");
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("Pacote L3: IP\n");
        intercept_packet_ip(eth_header, packet_header);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        printf("Pacote L3: IPv6\n");
        intercept_packet_ipv6(eth_header, packet_header);
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("Pacote L3: ARP\n");
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Pacote L3: Reverse ARP\n");
    } else if (ntohs(eth_header->ether_type) == 0x893A) {
        printf("Pacote L3: IEEE 1905\n");
    } else {
        printf("EtherType desconhecido: 0x%4X\n", ntohs(eth_header->ether_type));
    }
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

static int make_address_string(char *buffer, struct sockaddr *addr, const char *tagname) {
    switch (addr->sa_family) {

    case AF_INET:
        return sprintf(buffer, "%s: %08x, ",
                       tagname, ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr));

    case AF_INET6:
        return sprintf(buffer, "%s: PF_INET6, ",
                       tagname);

    case PF_PACKET:
        return sprintf(buffer, "%s: PF_PACKET, ",
                       tagname);

    default:
        return sprintf(buffer, "%s: sa_family=%d, ",
                       tagname, addr->sa_family);
    }
}

void my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    print_packet_info(packet_body, *packet_header);
    return;
}

int main(int argc, char *argv[]) {
    char device[128];
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
     struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;

    pcap_if_t *first_if;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&first_if, errbuf) < 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // TODO: Bypass autoselecion by using argc/arg
    pcap_if_t *cur_if;
    for (cur_if = first_if ; cur_if ; cur_if = cur_if->next) {
        printf("name = %s, descriptoin=%s, flags=%x\n",
               cur_if->name, cur_if->description, cur_if->flags);
        unsigned char valido = 0;

        struct pcap_addr *cur_addr;
        for (cur_addr = cur_if->addresses ; cur_addr ; cur_addr = cur_addr->next) {
            int ret = 0;
            char buffer[256];
            ret += sprintf(buffer + ret, "\t");

            ret += make_address_string(buffer + ret, cur_addr->addr, "addr");

            if (cur_addr->netmask)
                ret += make_address_string(buffer + ret, cur_addr->netmask, "netmask");

            if (cur_addr->broadaddr)
                ret += make_address_string(buffer + ret, cur_addr->broadaddr, "broadaddr");

            if (cur_addr->dstaddr)
                ret += make_address_string(buffer + ret, cur_addr->dstaddr, "dstaddr");

            buffer[ret -2] = '\0'; // cut tail ", "

            puts(buffer);
            if (cur_addr->netmask){
                valido=1;
            }
        }
        if(valido){
            strcpy(device,cur_if->name);
            break;
        }
    }

    pcap_freealldevs(first_if);

    /* Live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            100, // ms
            error_buffer
        );

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}