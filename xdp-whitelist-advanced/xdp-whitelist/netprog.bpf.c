/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define NANOSECONDS_IN_SEC 1000000000ULL

// فقط نگهداری IPهای whitelisted
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} adv_whitelist_map SEC(".maps");

// ساختار برای نگهداری rate limit
struct rate_limit_val {
    __u64 last_ts;
    __u8 count;
    __u8 max_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct rate_limit_val);
} adv_rate_limit_map SEC(".maps");

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 offset;
    __u32 ip_src;
    __u8 *whitelisted;

    offset = sizeof(*eth);
    if (data + offset > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + offset;
        if ((void *)ip + sizeof(*ip) > data_end)
            return XDP_PASS;

        ip_src = ip->saddr;

        // چک کردن اگر در whitelist هست
        whitelisted = bpf_map_lookup_elem(&adv_whitelist_map, &ip_src);
        if (whitelisted) {
            return XDP_PASS;
        }

        // اگر نبود، rate limit را اعمال کن
        struct rate_limit_val *rl_val;
        __u64 now = bpf_ktime_get_ns();

        rl_val = bpf_map_lookup_elem(&adv_rate_limit_map, &ip_src);
        if (!rl_val) {
            // هنوز مقدارش توسط user-space ست نشده، پس Drop
            return XDP_DROP;
        }

        if (now - rl_val->last_ts < NANOSECONDS_IN_SEC) {
            if (rl_val->count >= rl_val->max_packets) {
                return XDP_DROP;
            } else {
                rl_val->count++;
                bpf_map_update_elem(&adv_rate_limit_map, &ip_src, rl_val, BPF_ANY);
            }
        } else {
            rl_val->last_ts = now;
            rl_val->count = 1;
            bpf_map_update_elem(&adv_rate_limit_map, &ip_src, rl_val, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
