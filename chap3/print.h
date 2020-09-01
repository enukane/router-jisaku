#ifndef _PRINT_H_
#define _PRINT_H_
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

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
char *arp_ip2str(u_int8_t *ip, char *buf, socklen_t size);
char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size);
int print_ether_header(struct ether_header *eh, FILE *fp);
int print_arp(struct ether_arp *arp, FILE *fp);
int print_ip_header(struct iphdr *iphdr, u_char *option, int option_len, FILE *fp);
int print_ip6_header(struct ip6_hdr *ip6, FILE *fp);
int print_icmp(struct icmp *icmp, FILE *fp);
int print_icmp6(struct icmp6_hdr *icmp6, FILE *fp);
int print_tcp(struct tcphdr *tcphdr, FILE *fp);
int print_udp(struct udphdr *udphdr, FILE *fp);

#endif