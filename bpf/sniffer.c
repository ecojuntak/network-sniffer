//go:build ignore

// sniffer.c — CO-RE eBPF program for the network sniffer.
//
// It attaches to the stable `sock:inet_sock_set_state` tracepoint and emits one
// event per TCP connection that becomes ESTABLISHED. Watching the state
// transition captures both the outbound (SYN_SENT -> ESTABLISHED) and inbound
// (SYN_RECV -> ESTABLISHED) sides with a single, ABI-stable hook that works for
// IPv4 and IPv6.
//
// PID/comm are NOT taken at the ESTABLISHED transition: that fires in softirq
// context (SYN-ACK receive path), so bpf_get_current_pid_tgid there returns an
// unrelated on-CPU task (swapper/ksoftirqd). Instead a kprobe on tcp_connect —
// which runs in the connecting task's process context — records the real
// pid/comm into pid_by_sock keyed by the struct sock pointer. The tracepoint
// then joins on that pointer to attach the correct owner to the emitted edge.
// The entry is freed on the socket's TCP_CLOSE transition.
//
// The emitted record layout MUST stay byte-for-byte in sync with the Go decoder
// in internal/decode/decode.go (58 bytes, packed).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

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

// pid_info is the process identity captured in process context at connect time.
struct pid_info {
	__u32 pid;
	char comm[16];
};

// pid_by_sock maps a struct sock pointer to the identity of the task that
// initiated the connection. Populated by the tcp_connect kprobe, read by the
// state-change tracepoint, freed on TCP_CLOSE. Sized for many concurrent
// connections per node; LRU evicts the oldest if it ever fills, degrading
// gracefully to no-PID (which resolves to the node/IP identity) rather than
// failing.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct pid_info);
} pid_by_sock SEC(".maps");

// Force BTF emission of the event type for userspace/bpf2go.
struct conn_event *unused_event __attribute__((unused));

// handle_tcp_connect records the connecting task's identity keyed by the socket
// pointer. tcp_connect runs in the process context of the connect() caller, so
// the PID/comm here are the real client owner.
SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct pid_info info = {};
	info.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&info.comm, sizeof(info.comm));
	bpf_map_update_elem(&pid_by_sock, &key, &info, BPF_ANY);
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	__u64 sk = (__u64)ctx->skaddr;

	// Free the pid_by_sock entry when the socket closes so the map does not
	// accumulate stale connections (LRU also protects it, but explicit cleanup
	// keeps it tight).
	if (ctx->newstate == TCP_CLOSE) {
		bpf_map_delete_elem(&pid_by_sock, &sk);
		return 0;
	}

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

	// Attach the connecting task recorded at tcp_connect. A miss (inbound
	// connections, which have no local tcp_connect, or a map eviction) leaves
	// pid=0/comm="" — the server side is dropped downstream by the ephemeral
	// dest-port rule, and pid=0 signals "no process context" to the resolver.
	struct pid_info *info = bpf_map_lookup_elem(&pid_by_sock, &sk);
	if (info) {
		e->pid = info->pid;
		__builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
