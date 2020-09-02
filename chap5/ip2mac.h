#ifndef _IP2MAC_H_
#define _IP2MAC_H_

ip2mac *ip2mac_search(int device_no, in_addr_t addr, u_char *hwaddr);
ip2mac *ip_to_mac(int device_no, in_addr_t addr, u_char *hwaddr);
int buffer_send_one(int device_no, ip2mac *ip2mac);
int append_send_req_data(int deviceno, int ip2mac_no);
int get_send_req_data(int *device_no, int *ip2mac_no);
int buffer_send();

#endif
