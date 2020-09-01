#include "router.h"

param __router_param = {"eth1", "eth2", 0, "192.168.0.254"};
struct in_addr __next_router;
device __device[2];
int __end_flag == 0;
pthread_t buf_tid;


int debug_printf(char *fmt,...)
{
    if (__router_param.debug_out) {
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

int debug_perror(char *msg)
{
    if (__router_param.debug_out) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return 0;
}

int
send_icmp_time_exceed(int device_no, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size)
{
    struct ether_header reh;
    struct iphdr rih;
    struct icmp icmp;
    u_char *ipptr;
    u_char *ptr, buf[1500];
    int len;

    memcpy(reh.ether_dhost, eh->ether_shost, 6);
    memcpy(reh.ether_shost, __device[device_no].hwaddr, 6);
    reh.ether_type = htons(ETHERTYPE_IP);

    rih.version = 4;
    rih.ihl = 20/4
    rih.tos = 0;
    rih.tot_len = htons(sizeof(struct icmp) + 64);
    rih.id = 0;
    rih.frag_off = 0;
    rih.ttl = 64;
    rih.protocol = IPPROTO_ICMP;
    rih.check = 0;
    rih.saddr = __device[device_no].addr.s_addr;
    rih.daddr = iphdr->saddr;

    rih.check = checksum((u_char *)&rih, sizeof(struct iphdr));

    icmp.icmp_type = ICMP_TIME_EXCEEDED;
    icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
    icmp.icmp_cksum = 0;
    icmp.icmp_void = 0;

    ipptr = data + sizeof(struct ether_header);

    icmp.icmp_cksum = checksum2((u_char *)&icmp, 8, ipptr, 64);

    ptr = buf;
    memcpy(ptr, &reh, sizeof(struct ether_header));
    ptr += sizeof(struct ether_header));
    memcpy(ptr, &rih, sizeof(struct iphdr));
    ptr += sizeof(struct iphdr);
    memcpy(ptr, &icmp, 8);
    ptr += 8;
    memcpy(ptr, ipptr, 64);
    ptr += 64;
    len = ptr - buf;

    debug_printf("write: sendicmp timeexceeded [%d] %d bytes\n", device_no, len);
    write(__device[device_no].sock, buf, len);

    return (0);
}

int
analyze_packet(int device_no, u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_header *eh;
    char buf[80];
    int tno;
    u_char hwaddr[MACADDRLEN];

    ptr = data;
    rest = size;

    if (rest < sizeof(struct ether_header)) {
        debug_printf("[%d] rest=%d is less than ether_header size\n", device_no, rest);
        return -1;
    }

    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    rest -= sizeof(struct ether_header);

    if (memcmp(&eh->ether_dhost, __device[device_no].hwaddr, MACADDRLEN) != 0) {
        debug_printf("[%d] dhost not match %s\n", device_no, my_ether_ntoa_r((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
        return -1;
    }

    if (ntohs(eh->ethyer_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp;
        
        if (rest < sizeof(struct ether_arp)) {
            debug_printf("[%d] rest(%d) < sizeof(struct ether_arp, %d)\n", device_no, rest, sizeof(struct ether_arp));
            return -1;
        }

        arp = (struct ether_arp *)ptr;
        ptr += sizeof(struct ether_arp);
        rest -= sizeof(struct ether_arp);

        if (arp->arp_op == htons(ARPOP_REQUEST)) {
            debug_printf("[%d] recv: ARP_REQUEST: %d bytesf\n", device_no, size);
            ip_to_mac(device_no, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        }

        if (arp->arp_op == htons(ARPOP_REPLY)) {
            debug_printf("[%d] recv: ARP_REPLY :%d bytes\n", device_no, size);
            ip_to_mac(device_no, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        }
    } else
    if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        struct iphdr *iphdr;
        u_char option[1500];
        int option_len;

        if (rest < sizeof(struct iphdr)) {
            debug_printf("[%d] rest %d < iphdrsize\n", device_no, rest);
            return -1;
        }

        iphdr = (struct iphdr *)ptr;
        ptr += sizeof(struct iphdr);
        rest -= sizeof(struct iphdr);

        option_len = iphdr->ihl * 4 - sizeof(struct iphdr);
        if (option_len > 0) {
            if (option_len >= 1500) {
                debug_printf("[%d] ip optionlen %d too big\n", device_no, option_len);
                return -1;
            }

            memcpy(option, ptr, option_len);
            ptr += option_len;
            rest -= option_len;
        }

        /* check checksum */
        if (check_ip_checksum(iphdr, option, option_len) == 0) [
            debug_printf("[%d] bad ip checksum\n", device_no);
            fprintf(fpd, "IP checksum error\n");
            return -1;
        ]

        /* check ttl */
        if (iphdr->ttl - 1 = 0) {
            debug_printf("[%d] iphdr->ttl == 0 error\n", device_no);
            send_icmp_time_exceed(device_no, eh, iphdr, data, size);
            return -1;
        }

        tno = (!deviceno);

        if ((iphdr->daddr & __device[device_no].netmask.s_addr) == __device[tno].subnet.s_addr) {
            ip2mac *ip2mac;

            debug_printf("[%d]:%s to target segment\n", device_no, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

            if (iphdr->daddr == __device[tno].addr.s_addr) {
                debug_printf("[%d]: recv myaddr\n", device_no);
                return 1;
            }

            ip2mac = ip_to_mac(tno, iphdr->daddr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0) {
                debug_printf("[%d] ip2mac error or sending\n", device_no);
                append_send_data(ip2mac, 1, iphdr->daddr, data, size);
                return -1;
            } else {
                memcpy(hwaddr, ip2mac->hwaddr, 6);
            }
        }
        else {
            ip2mac *ip2mac

            debug_printf("[%d] %s to next router\n", device_no, in_addr_t2str(iphdr->daddr, buf, sizeof(buf));
            
            ip2mac = ip_to_mac(tnos, __next_router.s_addr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.no != 0) {
                debug_printf("[%d] ip2mac error or sending\n", device_no);
                append_send_data(ip2mac, 1, __next_router.s_addr, data, size);
                return -1;
            } else {
                memcpy(hwaddr, ip2mac->hwaddr, MACADDRLEN);
            }

        }

        memcpy(eh->ether_dhost, hwaddr, 6);
        memcpy(eh->ether_shost, __defvice[tno].hwaddr, MACADDRLEN);

        iphdr->ttl--;
        iphdr->check = 0;
        iphdr->check = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, option_len);

        write(__device[tno].sock, data, size);

    }

    return 0;
}


int
router()
{
    struct pollfd targets[2];
    int nready, i, size;
    u_char buf[2048];

    targets[0].fd = __device[0].sock;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = __device[1].sock;
    targets[1].events = POLLIN | POLLERR;

    while (__end_flag == 0) {
        nready = poll(targets, 2, 100);
        switch (nready) {
        case -1:
            if (errno != EINTR) {
                debug_perror("poll");
            }
            break;
        case 0:
            break;
        default:
            for (i = 0; i < 2; i++) {
                if (targets[i].revents & (POLLIN|POLLERR)) {
                    size = read(__device[i].sock, buf, sizeof(buf));
                    if (size <= 0) {
                        debug_perror("read");
                    } else {
                        analyze_packet(i, buf, size);
                    }
                }
            }
            break;
        }
    }

    return 0;
}

/* it's ok to use sysctl */
int
disable_ip_forward()
{
    FILE *fp;
    
#define PATH_IPFORWARD "/proc/sys/net/ipv4/ip_forward"
    fp = fopen(PATH_IPFORWARD, "w");
    if (fp == NULL) {
        debug_printf("cannot write %s\n", PATH_IPFORWARD);
        return -1;
    }

    fputs("0", fp);
    fclose(fp);

    return 0;
}

void *
buf_thread(void *arg)
{
    buffer_send();
    return NULL;
}

void
end_signal(int sig)
{
    __end_flag = 1;
}

int main(int argc, char **argv, char **envp)
{
    char buf[80];
    pthread_attr_t attr;
    int status;


    inet_aton(__router_param.next_router, &__next_router);
    debug_printf("next router=%s\n", my_inet_ntoa_r(&__next_router, buf, sizeof(buf)));

    if (get_device_info(__router_param.device1, __device[0].hwaddr, &__device[0].addr, &__device[0].subnet, &__device[0].netmask) == -1) {
        debug_printf("get_device_info error %s\n", __router_param.device1);
        return -1;
    }
    if ((__device[0].sock = init_raw_socket(__router_param.device1, 0, 0,)) == -1) {
        debug_printf("inti_raw_socket error %s\n", __router_param.device1);
        return -1;
    }
    debug_printf("%s Ok\n", __router_param.device1);
    debug_printf("addr=%sf\n", my_inet_ntoa_r(&__device[0].addr, buf, sizeof(buf));
    debug_printf("subnet=%sf\n", my_inet_ntoa_r(&__device[0].subnet, buf, sizeof(buf));
    debug_printf("netmask=%sf\n", my_inet_ntoa_r(&__device[0].netmask, buf, sizeof(buf));

    if (get_device_info(__router_param.device1, __device[1].hwaddr, &__device[1].addr, &__device[1].subnet, &__device[1].netmask) == -1) {
        debug_printf("get_device_info error %s\n", __router_param.device2);
        return -1;
    }
    if ((__device[0].sock = init_raw_socket(__router_param.device2, 0, 0,)) == -1) {
        debug_printf("inti_raw_socket error %s\n", __router_param.device2);
        return -1;
    }
    debug_printf("%s Ok\n", __router_param.device2);
    debug_printf("addr=%sf\n", my_inet_ntoa_r(&__device[1].addr, buf, sizeof(buf));
    debug_printf("subnet=%sf\n", my_inet_ntoa_r(&__device[1].subnet, buf, sizeof(buf));
    debug_printf("netmask=%sf\n", my_inet_ntoa_r(&__device[1].netmask, buf, sizeof(buf));

    disable_ip_forward();

    pthread_attr_init(&attr);

    if ((status = pthread_create(&buf_tid, &attr, buf_thread, NULL) != 0) {
        debug_printf("pthread_create: %s\n", strerror(status));
    }

    signal(SIGINT, end_signal);
    signal(SIGTERM, end_signal);
    signal(SIGQUIT, end_signal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    debug_prntf("router start\n");
    router();
    debug_printf("router end\n");

    pthread_join(buf_tid, NULL);

    close(__device[0].sock);
    close(__device[1].sock);

    return 0;
    
}