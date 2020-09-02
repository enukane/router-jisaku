#ifndef _NETUTIL_H_
#define _NETUTIL_H_

#include "base.h"

typedef struct {
    struct ether_header eh;
    struct ether_arp arp;
} packet_arp;
 

int init_raw_socket(char *device, int promisc_flag, int ip_only);
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size);
char *inet_addr_t2str(in_addr_t addr, char *buf, socklen_t size);
int print_ether_header(struct ether_header *eh, FILE *fp);
int print_ip_header(struct iphdr *iphdr, FILE *fp);
int get_device_info(char *device, u_char hwaddr[MACADDRLEN], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask);
int send_arp_request_b(int sock, in_addr_t target_ip, u_char target_mac[MACADDRLEN], in_addr_t my_ip, u_char my_mac[MACADDRLEN]);
#endif