#ifndef _ROUTER_H_
#define _ROUTER_H_


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <pthread.h>

#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendbuf.h"

typedef struct {
    char *device1;
    char *device2;
    int debug_out;
    char *next_router;
} param;

#endif