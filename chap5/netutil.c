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
print_ip_header(struct iphdr *iphdr, FILE *fp)
{
    char buf[80];

    fprintf(fp, "ip------------------------------\n");
#define print_ip_elm(name, type) do { fprintf(fp, #name "=" type "\n", iphdr->name); } while (0)
    print_ip_elm(version, "%u");
    print_ip_elm(ihl, "%u");
    print_ip_elm(tos, "%x");
    print_ip_elm(tot_len, "%u");
    print_ip_elm(id, "%u");
    fprintf(fp, "frag_off=%x, %u\n", (ntohs(iphdr->frag_off) >> 13) & 0x07, ntohs(iphdr->frag_off) & 0x1FFF);
    print_ip_elm(ttl, "%u");
    print_ip_elm(protocol, "%u");
    print_ip_elm(check, "%x");
    fprintf(fp, "saddr=%s\n", inet_addr_t2str(iphdr->saddr, buf, sizeof(buf)));
    fprintf(fp, "daddr=%s\n", inet_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

    return 0;
#undef print_ip_elm
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
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name));
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) == -1) {
        perror("ioctl");
        close(sock);
        return -1;
    } 
    p = (u_char *)&ifreq.ifr_hwaddr.sa_data;
    memcpy(hwaddr, p, MACADDRLEN);
    printf("%u %s : device=%s, ifr_name=%s, addr=0x%02x\n", __LINE__, __func__, device, ifreq.ifr_name, hwaddr[5]);

    if (ioctl(sock, SIOCGIFADDR, &ifreq) == -1) {
        perror("ioctl");
        close(sock);
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
        close(sock);
        return -1;
    }
    memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
    *mask = addr.sin_addr;

    subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));

    close(sock);

    return 0;
}

int
send_arp_request_b(int sock, in_addr_t target_ip, u_char target_mac[MACADDRLEN], in_addr_t my_ip, u_char my_mac[MACADDRLEN])
{
    packet_arp arp;
    int total;
    u_char *p;
    u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    union {
        u_long l;
        u_char c[4];
    } lc;
    int i;

    arp.arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp.arp_hln = 6;
    arp.arp.arp_pln = 4;
    arp.arp.arp_op = htons(ARPOP_REQUEST);

    for (i = 0; i < MACADDRLEN; i++) {
        arp.arp.arp_sha[i] = my_mac[i];
    }
    for (i = 0; i < MACADDRLEN; i++) {
        arp.arp.arp_tha[i] = 0;
    }

    lc.l = my_ip;
    for (i = 0; i < 4; i++) {
        arp.arp.arp_tpa[i] = lc.c[i];
    }

    for (i = 0; i < MACADDRLEN; i++) {
        arp.eh.ether_dhost[i] = target_mac[i];
        arp.eh.ether_shost[i] = my_mac[i];
    }

    arp.eh.ether_type = htons(ETHERTYPE_ARP);

    memset(buf, 0, sizeof(buf));
    p = buf;

    memcpy(p, &arp.eh, sizeof(struct ether_header));
    p += sizeof(struct ether_header);
    memcpy(p, &arp.arp, sizeof(struct ether_arp));
    p += sizeof(struct ether_arp);
    total = p - buf;

    write(sock, buf, total);

    return 0;
}