#include "common.h"

// Mapa LRU de IPs bloqueadas (L2/L3 Fast-Path O(1))
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_ENTRIES);
    __type(key, __u32);          // IPv4 en network-byte order
    __type(value, struct block_meta);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_ingress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parsing de cabecera Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parsing de cabecera IP
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;

    // 3. Busqueda en tabla hash LRU: Complejidad O(1)
    struct block_meta *meta = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (meta) {
        __sync_fetch_and_add(&meta->dropped_packets, 1);
        // Descarte directo en el driver de red (sin asignar sk_buff)
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
