#include "common.h"

// SOCKMAP donde se mantienen las referencias a los sockets activos
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

// Ring buffer para notificar al motor L7 en user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hook sock_ops: Se ejecuta cuando se establece la conexion TCP
SEC("sockops")
int bpf_sockmap_handler(struct bpf_sock_ops *skops) {
    if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        
        __u32 key = 0;
        // Registro en SOCKMAP mediante bpf_sock_map_update
        bpf_sock_map_update(skops, &sock_map, &key, BPF_NOEXIST);
    }
    return 0;
}

// Hook sk_msg: Intercepcion sincrona antes de la entrega al socket (sys_recvmsg)
SEC("sk_msg")
int bpf_sk_msg_parser(struct sk_msg_md *msg) {
    void *data = (void *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;

    if (data >= data_end)
        return SK_PASS;

    char *p = (char *)data;

    // Escanear ventana inicial del stream buscando la firma SQLi ("SELECT")
    #pragma unroll
    for (int i = 0; i < 200; i++) {
        if ((void *)(p + i + 6) > data_end)
            break;

        if (p[i] == 'S' && p[i+1] == 'E' && p[i+2] == 'L' &&
            p[i+3] == 'E' && p[i+4] == 'C' && p[i+5] == 'T') {
            
            // Estampar reloj monotono de alta resolucion en nanosegundos
            __u64 now_ns = bpf_ktime_get_ns();

            struct security_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (event) {
                event->kernel_ns = now_ns;
                event->src_ip = msg->remote_ip4;
                event->src_port = msg->remote_port;
                event->dst_port = msg->local_port;

                #pragma unroll
                for (int j = 0; j < 64; j++) {
                    if ((void *)(p + i + j + 1) <= data_end) {
                        event->payload_snippet[j] = p[i + j];
                    } else {
                        event->payload_snippet[j] = '\0';
                        break;
                    }
                }
                bpf_ringbuf_submit(event, 0);
            }

            // Descarta de forma sincrona el buffer (Cero fuga de primer paquete)
            return SK_DROP;
        }
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
