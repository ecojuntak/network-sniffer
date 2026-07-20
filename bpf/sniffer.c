//go:build ignore

// sniffer.c — CO-RE eBPF program for the network sniffer.
//
// It attaches to the stable `sock:inet_sock_set_state` tracepoint and emits one
// event per TCP connection that becomes ESTABLISHED. Watching the state
// transition (rather than a kprobe on tcp_connect) captures both the outbound
// (SYN_SENT -> ESTABLISHED) and inbound (SYN_RECV -> ESTABLISHED) sides with a
// single, ABI-stable hook that works for IPv4 and IPv6.
//
// The emitted record layout MUST stay byte-for-byte in sync with the Go decoder
// in internal/decode/decode.go (58 bytes, packed).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

// conn_event mirrors the Go wire format exactly. __attribute__((packed))
// guarantees no compiler padding so the 58-byte layout is stable.
struct conn_event {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport; // network byte order
	__u16 dport; // network byte order
	__u8 family;
	__u8 protocol;
	__u32 pid; // host byte order
	char comm[16];
} __attribute__((packed));

// Ring buffer carrying events to userspace (256 KiB).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Force BTF emission of the event type for userspace/bpf2go.
struct conn_event *unused_event __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	// Only care about connections reaching ESTABLISHED.
	if (ctx->newstate != TCP_ESTABLISHED)
		return 0;

	__u16 family = ctx->family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));

	if (family == AF_INET) {
		e->family = AF_INET;
		bpf_probe_read_kernel(e->saddr, 4, ctx->saddr);
		bpf_probe_read_kernel(e->daddr, 4, ctx->daddr);
	} else {
		e->family = AF_INET6;
		bpf_probe_read_kernel(e->saddr, 16, ctx->saddr_v6);
		bpf_probe_read_kernel(e->daddr, 16, ctx->daddr_v6);
	}

	// Tracepoint ports are host order; store network order to match the
	// decoder's big-endian read.
	e->sport = bpf_htons(ctx->sport);
	e->dport = bpf_htons(ctx->dport);
	e->protocol = (__u8)ctx->protocol;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
