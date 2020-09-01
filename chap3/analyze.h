#ifndef _ANALYZE_H_
#define _ANALYZE_H_

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


int analyze_arp(u_char *data, int size);
int analyze_icmp(u_char *data, int size);
int analyze_icmp6(u_char *data, int size);
int analyze_tcp(u_char *data, int size);
int analyze_udp(u_char *data, int size);
int analyze_ip(u_char *data, int size);
int analyze_ipv6(u_char *data, int size);
int analyze_packet(u_char *data, int size);

#endif