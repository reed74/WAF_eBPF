# Arquitectura Hibrida eBPF/XDP WAF para Mitigacion de Amenazas Web en Espacio de Kernel

Este proyecto implementa y valida una arquitectura desacoplada de dos planos (*two-plane architecture*) para la defensa reactiva y mitigacion de ataques a aplicaciones web de alta concurrencia, resolviendo el problema formal del *First-Payload Leakage* mediante inspeccion sincrona L7 (`sk_msg`/`SOCKMAP`) y amortizacion perimetral en Capa 2/3 con `XDP_DROP` en complejidad $O(1)$.

---

## 1. Topologia y Componentes

```
[ Red Ingress ]
       │
       ▼
 [ Driver NIC ] ──( XDP Fast-Path: xdp_filter.bpf.c )
       │                     ▲
       │ XDP_PASS            │ BPF_MAP_TYPE_LRU_HASH (blocked_ips)
       ▼                     │ (Inyeccion reactiva O(1))
[ Pila TCP/IP Kernel ]       │
       │                     │
 [ sock_ops Hook ] ──► Registra socket en BPF_MAP_TYPE_SOCKMAP
       │
 [ sk_msg Hook ] (sock_filter.bpf.c)
       │
       ├─► [Peticion Maliciosa: "SELECT"] ──► SK_DROP (Cero Fuga)
       │                                         │
       │                                         ▼ (Ring Buffer de eventos)
       │                                  [ Agente WAF en Go ]
       │                                  - Evaluacion Multirregla CRS
       │                                  - Calculo de latencia en ns/us
       │                                  - Actualizacion atomica en Kernel
       ▼
 [ Backend Server ] (Recibe unicamente trafico conforme)
```

---

## 2. Estructura de Directorios

```text
ebpf-waf/
├── Makefile                # Automatizacion de compilacion, vmlinux y testbed veth
├── go.mod                  # Definicion de dependencias del modulo Go
├── benchmark.sh            # Script de evaluacion de latencias en ms/us
├── test_waf.sh             # Test suite automatizado end-to-end
├── bpf/
│   ├── common.h            # Cabecera compartida y estructuras con timestamp ns
│   ├── xdp_filter.bpf.c    # Fast-path L2/L3 en driver NIC
│   └── sock_filter.bpf.c   # Hook sock_ops + sk_msg para intercepcion sincrona
└── cmd/
    ├── waf-agent/
    │   └── main.go         # Agente de control Go, consumidor de RingBuf y motor CRS
    └── backend-server/
        └── main.go         # Servidor backend HTTP objetivo
```

---

## 3. Requisitos del Sistema

* Linux Kernel >= 5.15 con soporte BTF (`/sys/kernel/btf/vmlinux`).
* Herramientas: `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`, `gcc`, `make`, `bpftool`, `golang-go` (>= 1.20), `curl`.

---

## 4. Guia Rapida de Despliegue y Ejecucion

### Paso 1: Clonar y descargar dependencias
```bash
go mod tidy
```

### Paso 2: Generar vmlinux.h y compilar el proyecto
```bash
make vmlinux
make all
```

### Paso 3: Arrancar el Servidor Backend (Terminal 1)
```bash
./bin/backend
```

### Paso 4: Arrancar el Agente WAF con privilegios (Terminal 2)
```bash
sudo ./bin/waf-agent lo /sys/fs/cgroup
```
*(Para entornos con interfaces virtuales `veth`, ejecutar previamente `make testbed` y lanzar con `sudo ./bin/waf-agent veth-waf /sys/fs/cgroup`).*

### Paso 5: Validacion Experimental (Terminal 3)
```bash
chmod +x test_waf.sh benchmark.sh
./test_waf.sh
./benchmark.sh
```

---

## 5. Inspeccion en Vivo del Kernel con bpftool

* Listar programas eBPF cargados:
  ```bash
  sudo bpftool prog show name xdp_ingress_filter
  sudo bpftool prog show name bpf_sk_msg_parser
  ```
* Inspeccionar IPs bloqueadas en el Fast-Path:
  ```bash
  sudo bpftool map dump name blocked_ips
  ```
* Inspeccionar sockets registrados en SOCKMAP:
  ```bash
  sudo bpftool map dump name sock_map
  ```
