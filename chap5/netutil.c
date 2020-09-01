#include "router.h"

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

char *
my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size)
{
    inet_ntop(PF_INET, addr, buf, size);

    return buf;
}

char *
inet_addr_t2str(in_addr_t addr, char *buf, socklen_t size)
{
    struct in_addr a;

    a.s_addr = addr;
    inet_ntop(PF_INET, &a, buf, size);

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

int
get_device_info(char *device, u_char hwaddr[MACADDRLEN], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask)
{
    struct ifreq ifreq;
    struct sockaddr_in addr;
    int sock;
    u_char *p;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("sock");
        return -1;
    }

    memset(&ifreq, 0, sizeof(ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) == -1) {
        perror("ioctl");
        close(sock);
        return -1;
    } 
    p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
    memcpy(hwaddr, p, MACADDRLEN);

    if (ioctl(sock, SIOCGIFADDR, &ifreq) == -1) {
        perror("ioctl");
        close(soc);
        return -1;
    }

    if (ifreq.ifr_addr.sa_family != PF_INET) {
        printf("%s not PFINET\n", device);
        close(sock);
        return -1;
    } else {
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *uaddr = addr.sin_addr;
    }

    if (ioctl(sock, SIOCGIFNETMASK, &ifreq) == -1) {
        perror("ioctl");
        close(soc);
        return -1;
    }
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *mask = addr.sin_addr;

    subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));

    close(sock);

    return 0;
}