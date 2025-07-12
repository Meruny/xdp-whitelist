#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    const char *ip_str = argv[1];
    struct in_addr ip_addr;

    if (inet_aton(ip_str, &ip_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 1;
    }

    __u32 ip = ip_addr.s_addr;
    __u32 value = 1;

    int map_fd;

    if (file_exists("/sys/fs/bpf/whitelist_map")) {
        map_fd = bpf_obj_get("/sys/fs/bpf/whitelist_map");
        if (map_fd < 0) {
            perror("bpf_obj_get");
            return 1;
        }
    } else {
        fprintf(stderr, "Map not pinned, load and pin your BPF program first\n");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &ip, &value, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("IP %s added to whitelist\n", ip_str);
    close(map_fd);
    return 0;
}

