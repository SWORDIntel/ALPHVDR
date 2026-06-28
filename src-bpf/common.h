#ifndef __COMMON_H
#define __COMMON_H

#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256

struct event {
    int pid;
    int ppid;
    int uid;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
};

struct tls_hello_event {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u16 payload_len;
    __u8 payload[128];
};

#endif
