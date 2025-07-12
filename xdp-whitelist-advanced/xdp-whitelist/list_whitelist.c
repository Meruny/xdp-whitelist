#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>           // برای close()
#include <arpa/inet.h>        // برای inet_ntoa
#include <sys/types.h>        // انواع داده مثل __u32
#include <linux/bpf.h>        // برای تعریف‌های BPF
#include <bpf/libbpf.h>       // برای bpf_* توابع

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/adv_whitelist_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    __u32 key = 0, next_key;
    __u32 value;

    printf("Whitelisted IPs:\n");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            struct in_addr ip_addr;
            ip_addr.s_addr = next_key;
            printf("- %s\n", inet_ntoa(ip_addr));
        }
        key = next_key;
    }

    close(map_fd);
    return 0;
}

