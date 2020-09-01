#ifndef _BRIDGE_H_
#define _BRIDGE_H_

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
#include "netutil.h"

typedef struct {
    char *device1;
    char *device2;
    int debug_out;
} bridge_param;

typedef struct {
    int sock;
} bridge_device;



#endif