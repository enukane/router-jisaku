#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

static int
init_raw_socket(char *device, int promisc_flag, int ip_only)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int sock;


    if (ip_only) {
        if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
            perror("socket");
            return -1;
        }
    } else {
        if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            perror("socket");
            return -1;

        }
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name)-1);
    if(ioctl(sock, SIOCGIFINDEX, &ifreq) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    if (ip_only) {
        sa.sll_protocol = htons(ETH_P_IP);
    } else {
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    sa.sll_ifindex = ifreq.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (promisc_flag) {
        if (ioctl(sock, SIOCGIFFLAGS, &ifreq)< 0) {
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

static char *
my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

static int
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
main(int argc, char **argv, char **envp)
{
    int sock, size;
    u_char buf[2048];

    if (argc <= 1) {
        fprintf(stderr, "%s <dvice-name>", argv[0]);
    }

    if ((sock = init_raw_socket(argv[1], 0, 0)) == -1) {
        fprintf(stderr, "init_raw_socket failed ifname=%s\n", argv[1]);
        return -1;
    }

    while (1) {
        if ((size = read(sock, buf, sizeof(buf))) <= 0) {
            perror("read");
        } else {
            if (size >= sizeof(struct ether_header)) {
                print_ether_header((struct ether_header *)buf, stdout);
            } else {
                fprintf(stderr, "read size(%d) < %zd\n", size, sizeof(struct ether_header));
            }
        }
    }

    close(sock);

    return (0);
}

/*
 * vim: sw=4 ts=4 expandtab
 */