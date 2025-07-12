#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define BPF_OBJ_PATH "/sys/fs/bpf/whitelist_map"

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_map *map;
    int err;

    // بارگذاری فایل BPF
    obj = bpf_object__open_file("netprog.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    // بارگذاری برنامه BPF به کرنل
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // گرفتن struct bpf_map به جای فقط fd
    map = bpf_object__find_map_by_name(obj, "whitelist_map");
    if (!map) {
        fprintf(stderr, "Failed to find map by name\n");
        bpf_object__close(obj);
        return 1;
    }

    // پین کردن مپ
    err = bpf_map__pin(map, BPF_OBJ_PATH);
    if (err && errno != EEXIST) {
        perror("Failed to pin map");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program loaded and map pinned at %s\n", BPF_OBJ_PATH);

    // برنامه تا اینجا اجرا شد یعنی موفق بود
    return 0;
}

