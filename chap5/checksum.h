#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#include "router.h"

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

u_int16_t checksum(u_char *data, int len);
u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2);
int check_ip_checksum(struct iphdr *iphdr, u_char *option, int option_len);
int check_ip_data_checksum(struct iphdr *iphdr, u_char *data, int len);
int check_ip6_data_checksum(struct ip6_hdr *ip6, u_char *data, int len);

#endif