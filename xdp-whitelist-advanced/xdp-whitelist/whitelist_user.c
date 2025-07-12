#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// تعریف ساختار rate_limit که داخل BPF map می‌ریزیم
struct rate_limit {
    __u32 max_packets_per_sec;  // نرخ مجاز (مثلاً 10 بسته بر ثانیه)
    __u32 current_count;        // شمارنده فعلی بسته‌ها (باید BPF برنامه آپدیت کنه)
    __u64 last_reset_ns;        // زمان آخرین ریست شمارنده (باید BPF برنامه آپدیت کنه)
};

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <max_packets_per_sec>\n", argv[0]);
        return 1;
    }

    const char *ip_str = argv[1];
    int max_pps = atoi(argv[2]);  // نرخ مجاز رو از آرگومان می‌گیریم

    if (max_pps <= 0) {
        fprintf(stderr, "Invalid max_packets_per_sec value: %d\n", max_pps);
        return 1;
    }

    struct in_addr ip_addr;
    if (inet_aton(ip_str, &ip_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_str);
        return 1;
    }

    __u32 ip = ip_addr.s_addr;

    struct rate_limit rl = {0};
    rl.max_packets_per_sec = max_pps;
    rl.current_count = 0;
    rl.last_reset_ns = 0;

    int map_fd;

    if (file_exists("/sys/fs/bpf/adv_whitelist_map")) {
        map_fd = bpf_obj_get("/sys/fs/bpf/adv_whitelist_map");
        if (map_fd < 0) {
            perror("bpf_obj_get");
            return 1;
        }
    } else {
        fprintf(stderr, "Map not pinned, load and pin your BPF program first\n");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &ip, &rl, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("IP %s added to whitelist with max_packets_per_sec = %d\n", ip_str, max_pps);
    close(map_fd);
    return 0;
}

