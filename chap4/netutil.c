#include "bridge.h"

int
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

char *
my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

int
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