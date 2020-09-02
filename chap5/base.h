#ifndef _BASE_H_
#define _BASE_H_

#define MACADDRLEN (6)

typedef struct {
    int sock;
    u_char hwaddr[MACADDRLEN];
    struct in_addr addr;
    struct in_addr subnet;
    struct in_addr netmask;
} device;

#define FLAG_FREE (0)
#define FLAG_OK (1)
#define FLAG_NG (-1)

typedef struct _data_buf_ {
    struct _data_buf_ *next;
    struct _data_buf_ *before;
    time_t t;
    int size;
    u_char *data;
} data_buf;

typedef struct {
    data_buf *top;
    data_buf *bottom;
    u_long dno;
    u_long in_bucket_size;
    pthread_mutex_t mutex;
} send_data;

typedef struct {
    int flag;
    int device_no;
    in_addr_t addr;
    u_char hwaddr[MACADDRLEN];
    time_t last_time;
    send_data sd;
} ip2mac;

#endif