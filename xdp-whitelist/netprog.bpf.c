/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_map SEC(".maps");

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 offset;
    __u32 ip_src;
    __u8 *exists;

    offset = sizeof(*eth);
    if (data + offset > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + offset;
        if ((void*)ip + sizeof(*ip) > data_end)
            return XDP_PASS;

        ip_src = ip->saddr;

        exists = bpf_map_lookup_elem(&whitelist_map, &ip_src);
        if (!exists) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

