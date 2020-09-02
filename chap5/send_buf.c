#include "router.h"

#define MAX_BUCKET_SIZE (1024 * 1024)

int
append_send_data(ip2mac *ip2mac, int device_no, in_addr_t addr, u_char *data, int size)
{
    send_data *sd = &ip2mac->sd;
    data_buf *d;
    int status;
    char buf[80];

    if (sd->in_bucket_size > MAX_BUCKET_SIZE) {
        printf("%s: bucket overflow\n", __func__);
        return -1;
    }

    d = (data_buf *)malloc(sizeof(data_buf));
    if (d == NULL) {
        perror("malloc");
        return -1;
    }

    d->data = (u_char *)malloc(size);
    if (d->data == NULL) {
        perror("malloc");
        free(d);
        return -1;
    }

    d->next = d->before = NULL;
    d->t = time(NULL);
    d->size = size;
    memcpy(d->data, data, size);

    if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
        printf("%s: pthrea_mutex_lock:%s\n", __func__, strerror(status));
        free(d->data);
        free(d);
        return -1;
    }

    if (sd->bottom == NULL) {
        sd->top = sd->bottom = d;
    } else {
        sd->bottom->next = d;
        d->before = sd->bottom;
        sd->bottom = d;
    }

    sd->dno++;
    sd->in_bucket_size += size;
    pthread_mutex_lock(&sd->mutex);

    printf("%s: [%d] %s %d bytes (total=%lu:%lu bytes)\n", __func__, device_no, inet_addr_t2str(addr, buf, sizeof(buf)), size, sd->dno, sd->in_bucket_size);

    return 0;
}

int
get_send_data(ip2mac *ip2mac, int *size, u_char **data)
{
    send_data *sd = &ip2mac->sd;
    data_buf *d;
    int status;
    char buf[80];

    if (sd->top == NULL) {
        return -1;
    }

    if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
        printf("pthread_mutex %s\n", strerror(status));
        return -1;
    }

    d = sd->top;
    sd->top = d->next;
    if (sd->top == NULL) {
        sd->bottom = NULL;
    } else {
        sd->top->before = NULL;
    }
    sd->dno--;
    sd->in_bucket_size -= d->size;

    pthread_mutex_unlock(&sd->mutex);

    *size = d->size;
    *data = d->data;

    free(d);

    printf("%s: [%d] %s %d bytes\n", __func__, ip2mac->device_no, inet_addr_t2str(ip2mac->addr, buf, sizeof(buf)), *size);

    return 0;
}

int
free_send_data(ip2mac *ip2mac)
{
    send_data *sd = &ip2mac->sd;
    data_buf *ptr;
    int status;
    char buf[80];

    if (sd->top == NULL) {
        return 0;
    }

    if ((status = pthread_mutex_lock(&sd->mutex)) != 0) {
        printf("pthread_mutex_lock: %s\n", strerror(errno));
        return -1;
    }

    for (ptr = sd->top; ptr != NULL; ptr = ptr->next) {
        printf("%s: %s %lu\n", __func__, inet_addr_t2str(ip2mac->addr, buf, sizeof(buf)), sd->in_bucket_size);
        free(ptr->data);
    }

    sd->top = sd->bottom = NULL;
    
    pthread_mutex_unlock(&sd->mutex);

    printf("%s: [%d]\n", __func__, ip2mac->device_no);

    return 0;

}