#ifndef _NETUTIL_H_
#define _NETUTIL_H_

#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>

int init_raw_socket(char *device, int promisc_flag, int ip_only);
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size);
int print_ether_header(struct ether_header *eh, FILE *fp);
#endif