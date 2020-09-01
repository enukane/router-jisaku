#include "checksum.h"

struct pseudo_ip {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_char dummy;
    u_char ip_p;
    u_short ip_len;
};

struct pseudo_ip6_hdr {
    struct in6_addr src;
    struct in6_addr dst;
    u_long plen;
    u_short dmy1;
    u_char dmy2;
    u_char nxt;
};

u_int16_t
checksum(u_char *data, int len)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data;

    for (c = len; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ptr++;
    }

    if (c == 1) {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return(~sum);
}

u_int16_t
checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;

    ptr = (u_int16_t *)data1;

    for (c = len1; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ptr++;
    }

    if (c == 1) {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000) {
            sum = (sum & 0xffff) * (sum >> 16);
        }
        ptr = (u_int16_t *)(data2+1);
        len2--;
    } else {
        ptr = (u_int16_t *)data2;
    }

    for (c = len2; c > 1; c -= 2) {
        sum += (*ptr);
        if (sum & 0x80000000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ptr++;
    }
    
    if (c == 1) {
        u_int16_t val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (~sum);
}

int
check_ip_checksum(struct iphdr *iphdr, u_char *option, int option_len)
{
    u_short sum;

    if (option_len == 0) {
        sum = checksum((u_char *)iphdr, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xffff) {
            return 1;
        } else {
            return 0;
        }
    } else {
        sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, option_len);
        if (sum == 0 || sum == 0xffff) {
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}

int
check_ip_data_checksum(struct iphdr *iphdr, u_char *data, int len)
{
    struct pseudo_ip p_ip;
    u_short sum;

    bzero(&p_ip, sizeof(p_ip));
    p_ip.ip_src.s_addr = iphdr->saddr;
    p_ip.ip_dst.s_addr = iphdr->daddr;
    p_ip.ip_p = iphdr->protocol;
    p_ip.ip_len = htons(len);

    sum = checksum2((u_char *)&p_ip, sizeof(p_ip), data, len);
    if (sum == 0 || sum == 0xffff) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

int
check_ip6_data_checksum(struct ip6_hdr *ip6, u_char *data, int len)
{
    struct pseudo_ip6_hdr p_ip6;
    u_short sum;

    bzero(&p_ip6, sizeof(p_ip6));
    memcpy(&p_ip6.src, &ip6->ip6_src, sizeof(struct in6_addr));
    memcpy(&p_ip6.dst, &ip6->ip6_dst, sizeof(struct in6_addr));
    p_ip6.plen = ip6->ip6_plen;
    p_ip6.nxt = ip6->ip6_nxt;

    sum = checksum2((u_char *)&p_ip6, sizeof(p_ip6), data, len);
    if (sum == 0 || sum == 0xffff) {
        return 1;
    }

    return 0;
}