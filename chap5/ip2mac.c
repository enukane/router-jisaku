#include "router.h"
#include "base.h"

#define IP2MAC_TIMEOUT_SEC  (60)
#define IP2MAC_NG_TIMEOUT_SEC   (1)

struct {
    ip2mac *data;
    int size;
    int no;
} ip2macs[2];

extern device __device[2];
extern int __arp_sock[2];
extern int __end_flag;

ip2mac *
ip2mac_search(int device_no, in_addr_t addr, u_char *hwaddr)
{
    register int i;
    int free_no, no;
    time_t now;
    char buf[80];
    ip2mac *ip2mac;

    free_no = -1;
    now = time(NULL);

    for (i = 0; i < ip2macs[device_no].no; i++) {
        ip2mac = &ip2macs[device_no].data[i];
        if (ip2mac->flag == FLAG_FREE) {
            if (free_no == -1) {
                free_no = i;
            }
            continue;
        }
        if (ip2mac->addr == addr) {
            if (ip2mac->flag == FLAG_OK) {
                ip2mac->last_time = now;
            }
            if (hwaddr != NULL) {
                memcpy(ip2mac->hwaddr, hwaddr, MACADDRLEN);
                ip2mac->flag = FLAG_OK;
                if (ip2mac->sd.top != NULL) {
                    append_send_req_data(device_no, i);
                }
                printf("ip2mac exist [%d] %s = %d\n", device_no, inet_addr_t2str(addr, buf, sizeof(buf)), i);
                return ip2mac;
            } else {
                if ((ip2mac->flag == FLAG_OK && (now - ip2mac->last_time) > IP2MAC_TIMEOUT_SEC)
                    || (ip2mac->flag == FLAG_NG && (now - ip2mac->last_time) > IP2MAC_NG_TIMEOUT_SEC)) {
                        free_send_data(ip2mac);
                        ip2mac->flag = FLAG_FREE;
                        printf("ip2mac FREE [%d] %s = %d\n", device_no, inet_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);
                        if (free_no == -1) {
                            free_no = i;
                        }
                } else {
                    printf("ip2mac EXIST [%d] %s = %d\n", device_no, inet_addr_t2str(addr, buf, sizeof(buf)), i);
                    return ip2mac;
                }
            }
        } else {
            if((ip2mac->flag == FLAG_OK && now - ip2mac->last_time > IP2MAC_TIMEOUT_SEC) ||
               (ip2mac->flag == FLAG_NG && now - ip2mac->last_time > IP2MAC_NG_TIMEOUT_SEC)) {
                free_send_data(ip2mac);
                ip2mac->flag = FLAG_FREE;
                printf("ip2mac FREE [%d] %s = %d\n", device_no, inet_addr_t2str(ip2mac->addr, buf, sizeof(buf)), i);
                if (free_no == -1) {
                    free_no = i;
                }
            }
        }
    }

    if (free_no == -1) {
        no = ip2macs[device_no].no;
        if (no >= ip2macs[device_no].size) {
            if (ip2macs[device_no].size == 0) {
                ip2macs[device_no].size = 1024;
                ip2macs[device_no].data = (void *)malloc(ip2macs[device_no].size * sizeof(ip2mac));
            } else {
                ip2macs[device_no].size += 1024;
                ip2macs[device_no].data = (void *)realloc(ip2macs[device_no].data, ip2macs[device_no].size * sizeof(ip2mac));
            }
        }
        ip2macs[device_no].no++;
    } else {
        no = free_no;
    }

    ip2mac = &ip2macs[device_no].data[no];
    ip2mac->device_no = device_no;
    ip2mac->addr = addr;
    if (hwaddr == NULL) {
        ip2mac->flag = FLAG_NG;
        bzero(ip2mac->hwaddr, MACADDRLEN);
    } else {
        ip2mac->flag = FLAG_OK;
        memcpy(ip2mac->hwaddr, hwaddr, MACADDRLEN);
    }

    ip2mac->last_time = now;
    memset(&ip2mac->sd, 0, sizeof(send_data));
    pthread_mutex_init(&ip2mac->sd.mutex, NULL);

    printf("ip2mac add [%d] %s = %d\n", device_no, inet_addr_t2str(ip2mac->addr, buf, sizeof(buf)), no);

    return ip2mac;
}

ip2mac *
ip_to_mac(int device_no, in_addr_t addr, u_char *hwaddr)
{
    ip2mac *ip2mac;
    static u_char bcast[MACADDRLEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char buf[80];

    ip2mac = ip2mac_search(device_no, addr, hwaddr);
    if (ip2mac->flag == FLAG_OK) {
        printf("ip_to_mac (%s): Ok\n", inet_addr_t2str(addr, buf, sizeof(buf)));
        return ip2mac;
    } else {
        printf("ip_to_mac (%s): Ng\n", inet_addr_t2str(addr, buf, sizeof(buf)));
        printf("ip_to_mac (%s): send arp request\n", inet_addr_t2str(addr, buf, sizeof(buf)));
        send_arp_request_b(__device[device_no].sock, addr, bcast, __device[device_no].addr.s_addr, __device[device_no].hwaddr);
        return ip2mac;
    }
}

int
buffer_send_one(int device_no, ip2mac *ip2mac)
{
    struct ether_header eh;
    struct iphdr iphdr;
    u_char option[1500];
    int option_len;
    int size;
    u_char *data;
    u_char *ptr;

    while (1) {
        if (get_send_data(ip2mac, &size, &data) == -1) {
            break;
        }

        ptr = data;

        memcpy(&eh, ptr, sizeof(struct ether_header));
        ptr += sizeof(struct ether_header);

        memcpy(&iphdr, ptr, sizeof(struct iphdr));
        ptr += sizeof(struct iphdr);

        option_len = iphdr.ihl * 4 - sizeof(struct iphdr);
        if (option_len > 0) {
            memcpy(option, ptr, option_len);
            ptr += option_len;
        }

        memcpy(eh.ether_dhost, ip2mac->hwaddr, MACADDRLEN);
        memcpy(data, &eh, sizeof(struct ether_header));

        printf("iphdr.ttl %d->%d\n", iphdr.ttl, iphdr.ttl - 1);
        iphdr.ttl--;

        iphdr.check = 0;
        iphdr.check = checksum2((u_char *)&iphdr, sizeof(struct iphdr), option, option_len);
        memcpy(data + sizeof(struct ether_header), &iphdr, sizeof(struct iphdr));

        printf("write:buffer_send_one: [%d] %d bytes\n", device_no, size);
        write(__device[device_no].sock, data, size);

        printf("*********[%d]\n", device_no);
        print_ether_header(&eh, stdout);
        print_ip_header(&iphdr, stdout);
        printf("*********[%d]\n", device_no);
    }

    return 0;
}

typedef struct _send_req_data_ {
    struct _send_req_data_ *next;
    struct _send_req_data_ *before;
    int device_no;
    int ip2mac_no;
} send_req_data;

struct {
    send_req_data *top;
    send_req_data *bottom;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} send_req = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

int
append_send_req_data(int device_no, int ip2mac_no)
{
    send_req_data *d;
    int status;
    if ((status = pthread_mutex_lock(&send_req.mutex)) != 0) {
        printf("append_send_req_data: pthread_mutex_lock: %s\n", strerror(status));
        return -1;
    }

    for (d = send_req.top; d != NULL; d = d->next) {
        if (d->device_no == device_no && d->ip2mac_no == ip2mac_no) {
            pthread_mutex_unlock(&send_req.mutex);
            return 1;
        }
    }

    d = (send_req_data *)malloc(sizeof(send_req_data));
    if (d == NULL) {
        printf("append_send_req_data:malloc");
        pthread_mutex_unlock(&send_req.mutex);
        return -1;
    }

    d->next = d->before = NULL;
    d->device_no = device_no;
    d->ip2mac_no = ip2mac_no;

    if (send_req.bottom == NULL) {
        send_req.top = send_req.bottom = d;
    } else {
        send_req.bottom->next = d;
        d->before = send_req.bottom;
        send_req.bottom = d;
    }

    pthread_cond_signal(&send_req.cond);
    pthread_mutex_unlock(&send_req.mutex);

    printf("append_send_req_data [%d] %d\n", device_no, ip2mac_no);

    return 0;
}

int
get_send_req_data(int *device_no, int *ip2mac_no)
{
    send_req_data *d;
    int status;

    if (send_req.top == NULL) {
        return -1;
    }

    if ((status = pthread_mutex_lock(&send_req.mutex)) != 0) {
        printf("pthread_mutex_lock: %s\n", strerror(status));
        return -1;
    }

    d = send_req.top;
    send_req.top = d->next;

    if (send_req.top == NULL) {
        send_req.bottom = NULL;
    } else {
        send_req.top->before = NULL;
    }

    pthread_mutex_unlock(&send_req.mutex);

    *device_no = d->device_no;
    *ip2mac_no = d->ip2mac_no;

    printf("get_send_req_data: [%d] %d\n", *device_no, *ip2mac_no);

    return 0;
}

int
buffer_send()
{
    struct timeval now;
    struct timespec timeout;
    int device_no, ip2mac_no;
    int status;


    while (__end_flag == 0) {
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + 1;
        timeout.tv_nsec = now.tv_usec * 1000;

        pthread_mutex_lock(&send_req.mutex);
        if ((status = pthread_cond_timedwait(&send_req.cond, &send_req.mutex, &timeout)) != 0) {
            printf("pthread_cond_timedwait: %s\n", strerror(status));
        }
        pthread_mutex_unlock(&send_req.mutex);

        while (1) {
            if (get_send_req_data(&device_no, &ip2mac_no) == -1) {
                break;
            }
            buffer_send_one(device_no, &ip2macs[ip2mac_no].data[ip2mac_no]);
        }
    }

    printf("buffer_send: end\n");

    return 0;
}