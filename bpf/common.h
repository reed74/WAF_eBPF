#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define MAX_BLOCKED_ENTRIES 100000

/* Metadata almacenada en la tabla hash LRU de IPs bloqueadas (L2/L3) */
struct block_meta {
    __u64 timestamp_ns;
    __u64 dropped_packets;
};

/* Evento transmitido a espacio de usuario con sello temporal de alta resolucion (ns) */
struct security_event {
    __u64 kernel_ns;              /* Sello de tiempo capturado por bpf_ktime_get_ns() */
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    char payload_snippet[128];
};

#endif /* __COMMON_H__ */
