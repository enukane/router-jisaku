#include "bridge.h"

bridge_param __bparam = { "eth0", "eth1", 1};
bridge_device __bdev[2];

int __end_flag = 0;

int debug_printf(char *fmt,...)
{
    if (__bparam.debug_out) {
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

int debug_perror(char *msg)
{
    if (__bparam.debug_out) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return 0;
}

int
analyze_packet(int device_no, u_char *data, int size)
{
    u_char *ptr;
    int rest;
    struct ether_header *eh;

    ptr = data;
    rest = size;

    if (rest < sizeof(struct ether_header)) {
        debug_printf("[%d] rest=%d is less than ether_header size\n", device_no, rest);
        return -1;
    }

    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    rest -= sizeof(struct ether_header);

    debug_printf("[%d] ", device_no);
    if (__bparam.debug_out) {
        print_ether_header(eh, stderr);
    }

    return 0;
}

int
bridge()
{
    struct pollfd targets[2];
    int nready, i, size;
    u_char buf[2048];

    targets[0].fd = __bdev[0].sock;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = __bdev[1].sock;
    targets[2].events = POLLIN | POLLERR;

    while (__end_flag == 0) {
        switch (nready = poll(targets, 2, 100)) {
        case -1:
            if (errno != EINTR) {
                perror("poll");
            }
            break;
        case 0:
            break;
        default:
            for (i = 0; i < 2; i++) {
                if (targets[i].revents & (POLLIN|POLLERR)) {
                    size = read(__bdev[i].sock, buf, sizeof(buf));
                    if (size <= 0) {
                        perror("read");
                    } else {
                        if (analyze_packet(i, buf, size) != -1) {
                            size = write(__bdev[(!i)].sock, buf, size);
                            if (size <= 0) {
                                perror("write");
                            } else {
                                debug_printf("bridge forward packet from %d to %d (size=%d)\n", i, !i, size);
                            }
                        }
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

void
end_signal(int sig)
{
    __end_flag = 1;
}

int
main(int argc, char **argv, char **envp)
{

    if (argc == 3) {
        __bparam.device1 = strdup(argv[1]);
        __bparam.device2 = strdup(argv[2]);
    }

    __bdev[0].sock = init_raw_socket(__bparam.device1, 1, 0);
    if (__bdev[0].sock == -1) {
        debug_printf("init_raw_socket: error %s\n", __bparam.device1);
        return -1;
    }
    debug_printf("%s Ok\n", __bparam.device1);

    __bdev[1].sock = init_raw_socket(__bparam.device2, 1, 0);
    if (__bdev[1].sock == -1) {
        debug_printf("init_raw_socket: error %s\n", __bparam.device2);
        return -1;
    }

    debug_printf("%s Ok\n", __bparam.device2);

    disable_ip_forward();

    signal(SIGINT, end_signal);
    signal(SIGTERM, end_signal);
    signal(SIGQUIT, end_signal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    debug_printf("bridge start\n");
    bridge();
    debug_printf("bridge terminated\n");

    close(__bdev[0].sock);
    close(__bdev[1].sock);

    return 0;
}