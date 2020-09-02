#ifndef _SEND_BUF_H_
#define _SEND_BUF_H_
int append_send_data(ip2mac *ip2mac, int device_no, in_addr_t addr, u_char *data, int size);
int get_send_data(ip2mac *ip2mac, int *size, u_char **data);
int free_send_data(ip2mac *ip2mac);

#endif