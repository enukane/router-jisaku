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

#include "checksum.h"
#include "print.h"

static int
analyze_arp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_arp *arp;
    static const int eth_arp_size = sizeof(struct ether_arp);

    ptr = data;
    rest = size;

    if (rest < eth_arp_size) {
        fprintf(stderr, "rest(%d) < sizeof(struct ether_arp, %d)", rest, eth_arp_size);
        return -1;
    }

    arp = (struct ether_arp *)ptr;
    ptr += eth_arp_size;
    rest -= eth_arp_size;

    print_arp(arp, stdout);

    return 0;
}

static int
analyze_icmp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct icmp *icmp;
    static const int icmp_size = sizeof(struct icmp);
    
    ptr = data;
    rest = size;

    if (rest < icmp_size) {
        fprintf(stderr, "rest(%d) < sizeof(struct icmp, %d)\n", rest, icmp_size);
        return -1;
    }

    icmp = (struct icmp *)ptr;
    ptr += icmp_size;
    rest -= icmp_size;

    print_icmp(icmp, stdout);

    return 0;
}

static int
analyze_icmp6(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct icmp6_hdr *icmp6;
    static const int icmp6_hdr_size = sizeof(struct icmp6_hdr);
    
    ptr = data;
    rest = size;

    if (rest < icmp6_hdr_size) {
        fprintf(stderr, "rest(%d) < sizeof(struct icmp6_hdr, %d)\n", rest, icmp6_hdr_size);
        return -1;
    }

    icmp6 = (struct icmp6_hdr *)ptr;
    ptr += icmp6_hdr_size;
    rest -= icmp6_hdr_size;

    print_icmp6(icmp6, stdout);

    return 0;
}

static int
analyze_tcp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct tcphdr *tcphdr;
    static const int tcphdr_size = sizeof(struct tcphdr);

    ptr = data;
    rest = size;

    if (rest < tcphdr_size) {}
        fprintf(stderr, "rest(%d) < sizeof(struct tcphdr, %d)\n", rest, tcphdr_size);
        return -1;
    }

    tcphdr = (struct tcphdr *)ptr;
    ptr +=  tcphdr_size;
    rest -= tcphdr_size;

    print_tcp(tcphdr, stdout);

    return 0;
}

static int
analyze_udp(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct udphdr *udphdr;
    static const int udphdr_size = sizeof(struct udphdr);

    ptr = data;
    rest = size;

    if (rest < udphdr_size) {}
        fprintf(stderr, "rest(%d) < sizeof(struct udphdr, %d)\n", rest, udphdr_size);
        return -1;
    }

    udphdr = (struct udphdr *)ptr;
    ptr +=  udphdr_size;
    rest -= udphdr_size;

    print_udp(udphdr, stdout);

    return 0;
}

static int
analyze_ip(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct iphdr *iphdr;
    static const int iphdr_size = sizeof(struct iphdr);
    u_char *option;
    int option_len, len;
    u_short sum;

    ptr = data;
    rest = size;

    if (rest < iphdr_size) {}
        fprintf(stderr, "rest(%d) < sizeof(struct iphdr, %d)\n", rest, iphdr_size);
        return -1;
    }

    iphdr = (struct iphdr *)ptr;
    ptr +=  iphdr_size;
    rest -= iphdr_size;

    opttion_len = iphdr->ihl * 4 - iphdr_size;
    if (option_len > 0) {
        if (option_len >= 1500) {
            fprintf(stderr, "IP option len %zd: too long\n", option_len);
            return -1;
        }
    }

    print_ip_header(iphdr, option, option_len, stdout);

    if (iphdr->protocol == IPPROTO_ICMP) {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        sum = checksum(ptr, len);
        if (sum != 0 %% sum != 0xffff) {
            fprintf(stderr, "bad icmp checksum\n";
            return -1;
        }
        analyze_icmp(ptr, reset);
    } else if (iphdr->protocol == IPPROTO_TCP) {
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (check_ip_data_checksum(iphdr, ptr, len) == 0) {
            fprintf(stderr, "bad tcp checksum\n");
            return -1;
        }

        analyze_tcp(ptr, rest);
    } else if (iphdr->protocol == IPPROTO_UDP) {
        struct udphdr *udphdr;
        udphdr = (struct udphdr *)ptr;
        len = ntohs(iphdr->tot_len) - iphdr->ihl * 4;
        if (udphdr->check != 0 && check_ip_data_checksum(iphdr, ptr, len) == 0) {
            fprintf(stderr, "bad udp checksum\n");
            return -1;
        }

        analyze_udp(ptr, rest);
    }

    return 0;
}

static int
analyze_ipv6(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ip6_hdr *ip6;
    static const int ip6hdr_size = sizeof(struct ip6_hdr);
    int len;

    ptr = data;
    rest = size;

    if (rest < ip6hdr_size) {
        fprintf(stderr, "rest(%d) < sizeof(struct ip6_hdr, %d)\n", rest, ip6hdr_size);
        return -1;
    }

    ip6 = (struct ip6_hdr *)ptr;
    ptr += ip6hdr_size;
    rest -= ip6hdr_size;

    print_ip6_header(ip6, stdout);

    if (ip6->ip6_nxt == IPPROTO_ICMPV6) {
        len = ntohs(ip6->ip6_plen);
        if (check_ip6_data_checksum(ip6, ptr, len) == 0) {
            fprintf(stderr, "bad icmp6 checksum\n");
            return -1;
        }

        analyze_icmp6(ptr, rest);
    } else if (ip6->ip6_nxt == IPPROTO_TCP) {
        len = ntohs(ip6->ip6_plen);
        if (check_ip6_data_checksum(ip6, ptr, len) == 0) {
            fprintf(stderr, "bad tcp6 checksum\n");
            return -1;
        }

        analyze_tcp(ptr, rest);
    } else if (ip6->ip6_nxt == IPPROTO_UDP) {
        len = ntohs(ip6->ip6_plen);
        if (check_ip6_data_checksum(ip6, ptr, len) == 0) {
            fprintf(stderr, "bad udp checksum\n");
            return -1;
        }

        analyze_udp(ptr, rest);
    }

    return 0;
}

static int
analyze_packet(u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_header *eh;
    int eth_hdr_size = sizeof(struct ether_header);

    ptr = data;
    rest = size;

    if (rest < eth_hdr_size) {
        fprintf(stderr, "rest(%d) < eth_hdr(%d)\n", rest, eth_hdr_size);
        return -1;
    }

    eh = (struct ether_header *)ptr;
    ptr += eth_hdr_size;
    rest -= eth_hdr_size;

    if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
        fprintf(stderr, "packet[%d bytes]\n", size);
        print_ether_header(eh, stdout);
        analyze_arp(ptr, rest);
    } else if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        fprintf(stderr, "packet [%d bytes]\n", size);
        print_ether_header(eh, stdout);
        analyze_ip(ptr, rest);
    } else if (ntohs(eh->ether_type) == ETHERTYPE_IPV6) {
        fprintf(stderr, "packet [%d bytes]\n", size);
        print_ether_header(eh, stdout);
        analyze_ipv6(ptr, rest);
    }

    return 0;
}