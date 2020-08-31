#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif


char *
my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

char *
arp_ip2str(u_int8_t *ip, char *buf, socklen_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

char *
ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
    struct in_addr *addr;

    addr = (struct in_addr *)&ip;
    inet_ntop(AF_INET, addr, buf, size);

    return buf;
}

int
print_ether_header(struct ether_header *eh, FILE *fp)
{
    char buf[80];
    
    fprintf(fp, "ether_header------------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%02x", ntohs(eh->ether_type));
    switch (ntohs(eh->ether_type)) {
    case ETH_P_IP:
        fprintf(fp, " (IP)\n");
        break;
    case ETH_P_IPV6:
        fprintf(fp, " (IPv6)\n");
        break;
    case ETH_P_ARP:
        fprintf(fp, " (ARP)\n");
        break;
    default:
        fprintf(fp, " (Unknown)\n");
        break;
    }

    return 0;
}

int
print_arp(struct ether_arp *arp, FILE *fp)
{
    fprintf(fp, "arp------------------------------\n");
    fprintf(fp, "arp_hrd=%u", ntohs(arp->arp_hrd));
    fprintf(fp, "\n");

    fprintf(fp, "arp_pro=%u", ntohs(arp->arp_pro));
    switch (ntohs(arp->arp_pro)) {
    case ETHERTYPE_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETHERTYPE_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    case ETHERTYPE_REVARP:
        fprintf(fp, "(RARP)\n");
        break;
    case ETHERTYPE_IPV6:
        fprintf(fp, "(IPV6)\n");
        break;
    default:
        fprintf(fp, "(Unknown)\n");
        break;
    }
    fprintf(fp, "arp_hln=%u\n", arp->arp_hln);
    fprintf(fp, "arp_pln=%u\n", arp->arp_pln);
    fprintf(fp, "arp_op=%u\n", ntohs(arp->arp_op));
    fprintf(fp, "arp_sha=%s\n", my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));
    fprintf(fp, "arp_spa=%s\n", my_ether_ntoa_r(arp->arp_spa, buf, sizeof(buf)));
    fprintf(fp, "arp_tha=%s\n", my_ether_ntoa_r(arp->arp_tha, buf, sizeof(buf)));
    fprintf(fp, "arp_tpa=%s\n", my_ether_ntoa_r(arp->arp_tpa, buf, sizeof(buf)));
    fprintf(fp, "arp_sha=%s\n", my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));

    return 0;
}

int
print_ip_header(struct iphdr *iphdr, u_char *option, int option_len, FILE *fp)
{
    char buf[80];

    fprintf(fp, "ip------------------------------\n");
#define print_ip_elm(name, type) do { fprintf(fp, #name "=" type "\n", iphdr->name)}
    print_ip_elm(version, "%u");
    print_ip_elm(ihl, "%u");
    print_ip_elm(tos, "%x");
    print_ip_elm(tot_len, "%u");
    print_ip_elm(id, "%u");
    fprintf(fp, "frag_off=%x, %u\n", (ntohs(iphdr->frag_off) >> 13) & 0x07, ntohs(iphdr->frag_off) & 0x1FFF);
    print_ip_elm(ttl, "%u");
    print_ip_elm(protocol, "%u");
    print_ip_elm(check, "%x");
    fprintf(fp, "saddr=%s\n", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
    fprintf(fp, "daddr=%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
    if (option_len > 0) {
        fprintf(fp, "option:\n ");
        for (i = 0; i < option_len; i++) {
            fprintf(fp, "%02x ", option[i]);
        }
        fprintf(fp, "\n");
    }

    return 0;
#undef print_ip_elm
}