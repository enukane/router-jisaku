#include "print.h"

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
    char buf[80];
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
#define print_ip_elm(name, type) do { fprintf(fp, #name "=" type "\n", iphdr->name); } while (0)
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
        for (int i = 0; i < option_len; i++) {
            fprintf(fp, "%02x ", option[i]);
        }
        fprintf(fp, "\n");
    }

    return 0;
#undef print_ip_elm
}

int
print_ip6_header(struct ip6_hdr *ip6, FILE *fp)
{
    char buf[80];
    fprintf(fp, "ip------------------------------\n");
#define print_ip6_elm(name, type) do { fprintf(fp, #name "=" type "\n", ip6->name); } while (0)
#define print_ip6_elm_ntohs(name, type) do { fprintf(fp, #name "=" type "\n", ntohs(ip6->name)); } while (0)

    print_ip6_elm(ip6_flow, "%x");
    print_ip6_elm_ntohs(ip6_plen, "%d");
    print_ip6_elm(ip6_nxt, "%u");
    print_ip6_elm(ip6_hlim, "%d");
    fprintf(fp, "ip6_src=%s\n", inet_ntop(AF_INET6, &ip6->ip6_src, buf, sizeof(buf)));
    fprintf(fp, "ip6_dst=%s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, buf, sizeof(buf)));

    return 0;

#undef print_ip6_elm
#undef print_ip6_elm_ntohs
}

int
print_icmp(struct icmp *icmp, FILE *fp)
{
    static char *icmp_type[] = {
        "Echo Reply",
        "undefined",
        "undefined",
        "Destination Unreachable",
        "Source Quench",
        "Redirect",
        "undefined",
        "undefined",
        "Echo Req",
        "Router Advertisement",
        "Router Selection",
        "Time Exceeded for Datagram",
        "Parameter Problem on Datagram",
        "Timestamp Request",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply"
    };

    fprintf(fp, "icmp-------------------------------------\n");
    fprintf(fp, "icmp_type=%u", icmp->icmp_type);
    if (icmp->icmp_type <= 18) {
        fprintf(fp, " (%s)\n", icmp_type[icmp->icmp_type]);
    } else {
        fprintf(fp, " (undefined)\n");
    }

    fprintf(fp, "icmp_code=%u\n", icmp->icmp_code);
    fprintf(fp, "icmp_id=%u\n", ntohs(icmp->icmp_id));
    fprintf(fp, "icmp_seq=%u\n", ntohs(icmp->icmp_seq));

    return 0;
}

int
print_icmp6(struct icmp6_hdr *icmp6, FILE *fp)
{
    const char *type_msg;

    fprintf(fp, "icmp-------------------------------------\n");
    fprintf(fp, "icmp6_type=%u ", icmp6->icmp6_type);
    switch (icmp6->icmp6_type) {
    case 1:
        type_msg = "Destination Unreachable";
        break;
    case 2:
        type_msg = "Packet too Big";
        break;
    case 3:
        type_msg = "Time Exceeded";
        break;
    case 4:
        type_msg = "Parameter Problem";
        break;
    case 128:
        type_msg = "Echo Request";
        break;
    case 129:
        type_msg = "Echo Reply";
        break;
    default:
        type_msg = "Undefined";
        break;
    }
    fprintf(fp, "(%s)\n", type_msg);

    fprintf(fp, "icmp6_code=%u\n", icmp6->icmp6_code);
    fprintf(fp, "icmp6_cksum=%u\n", ntohs(icmp6->icmp6_cksum));

    if (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129) {
        fprintf(fp, "icmp6_id=%u\n", ntohs(icmp6->icmp6_id));
        fprintf(fp, "icmp6_seq=%u\n", ntohs(icmp6->icmp6_seq));
    }

    return 0;
}

int
print_tcp(struct tcphdr *tcphdr, FILE *fp)
{
    fprintf(fp, "tcp------------------------------\n");
#define print_tcp_elm(name, type) do { fprintf(fp, #name "=" type "\n", tcphdr->name); } while (0)
#define print_tcp_elm_ntohs(name, type) do { fprintf(fp, #name "=" type "\n", ntohs(tcphdr->name)); } while (0)
#define print_tcp_elm_ntohl(name, type) do { fprintf(fp, #name "=" type "\n", ntohl(tcphdr->name)); } while (0)
    print_tcp_elm_ntohs(source, "%u");
    print_tcp_elm_ntohs(dest, "%u");
    print_tcp_elm_ntohl(seq, "%u");
    print_tcp_elm_ntohl(ack_seq, "%u");
    print_tcp_elm(doff, "%u");
    print_tcp_elm(urg, "%u");
    print_tcp_elm(ack, "%u");
    print_tcp_elm(psh, "%u");
    print_tcp_elm(rst, "%u");
    print_tcp_elm(syn, "%u");
    print_tcp_elm(fin, "%u");
    print_tcp_elm_ntohs(window, "%u");
    print_tcp_elm_ntohs(check, "%u");
    print_tcp_elm_ntohs(urg_ptr, "%u");

    return 0;
#undef print_tcp_elm
#undef print_tcp_elm_ntohs
#undef print_tcp_elm_ntohl
}

int
print_udp(struct udphdr *udphdr, FILE *fp)
{
    fprintf(fp, "udp------------------------------\n");
#define print_udp_elm(name, type) do { fprintf(fp, #name "=" type "\n", udphdr->name)} while (0)
#define print_udp_elm_ntohs(name, type) do { fprintf(fp, #name "=" type "\n", ntohs(udphdr->name)); } while (0)
#define print_udp_elm_ntohl(name, type) do { fprintf(fp, #name "=" type "\n", ntohl(udphdr->name)); } while (0)
    print_udp_elm_ntohs(source, "%u");
    print_udp_elm_ntohs(dest, "%u");
    print_udp_elm_ntohs(len, "%u");
    print_udp_elm_ntohs(check, "%u");

    return 0;
#undef print_udp_elm
#undef print_udp_elm_ntohs
#undef print_udp_elm_ntohl
}