#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include "analyze.h"


static
int init_raw_socket(char *device, int promisc, int ip_only)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int sock;
    int sock_type, sock_protocol;

    sock_type = SOCK_RAW;
    sock_protocol = ip_only ? htons(ETH_P_IP) : htons(ETH_P_ALL);

    if ((sock = socket(PF_PACKET, sock_type, sock_protocol)) < 0) {
        perror("socket");
        return -1;
    }


    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ip_only ? ETH_P_IP : ETH_P_ALL);
    sa.sll_ifindex = ifreq.ifr_ifindex;
    
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (promisc) {
        if (ioctl(sock, SIOCGIFFLAGS, &ifreq) < 0) {
            perror("ioctl");
            close(sock);
            return -1;
        }

        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(sock, SIOCSIFFLAGS, &ifreq) < 0) {
            perror("ioctl");
            close(sock);
            return -1;
        }
    }

    return sock;
}

int
main(int argc, char **argv, char **envp)
{
    int sock, size;
    u_char buf[65535];

    if (argc <= 1) {
        fprintf(stderr, "%s <dvice-name>\n", argv[0]);
        return 1;
    }

    if ((sock = init_raw_socket(argv[1], 0, 0) )== -1) {
        fprintf(stderr, "init_raw_socket failed ifname=%s\n", argv[1]);
        return -1;
    }

    while (1) {
        if ((size = read(sock, buf, sizeof(buf))) <= 0) {
            perror("read");
        } else {
            analyze_packet(buf, size);
        }
    }

    close(sock);

    return 0;
}