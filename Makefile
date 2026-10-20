CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86

.PHONY: all vmlinux bpf agent backend clean testbed clean-testbed

all: bpf agent backend

vmlinux:
	mkdir -p bpf
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf:
	mkdir -p bpf bin
	$(CLANG) $(CFLAGS) -c bpf/xdp_filter.bpf.c -o bpf/xdp_filter.bpf.o
	$(CLANG) $(CFLAGS) -c bpf/sock_filter.bpf.c -o bpf/sock_filter.bpf.o

agent:
	mkdir -p bin
	go build -o bin/waf-agent ./cmd/waf-agent/main.go

backend:
	mkdir -p bin
	go build -o bin/backend ./cmd/backend-server/main.go

testbed:
	sudo ip netns add waf-ns || true
	sudo ip link add veth-waf type veth peer name veth-client || true
	sudo ip link set veth-client netns waf-ns || true
	sudo ip addr add 10.200.1.1/24 dev veth-waf || true
	sudo ip link set veth-waf up || true
	sudo ip netns exec waf-ns ip addr add 10.200.1.2/24 dev veth-client || true
	sudo ip netns exec waf-ns ip link set veth-client up || true
	sudo ip netns exec waf-ns ip link set lo up || true

clean-testbed:
	sudo ip link delete veth-waf 2>/dev/null || true
	sudo ip netns delete waf-ns 2>/dev/null || true

clean:
	rm -rf bin/ bpf/*.o
