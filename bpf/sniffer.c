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
// The entry is consumed and freed when the connection reaches ESTABLISHED (or
// on TCP_CLOSE if it never does): an entry must never outlive its socket. A
// leaked entry keyed by a freed struct sock address can hit on a later,
// unrelated ACCEPTED socket that reuses the slab address, tagging it outbound
// with a stale pid/comm — which launders a mirrored server-side record past
// userspace's reversed-duplicate filter as a phantom edge carrying the
// caller's ephemeral port. (Close-time cleanup alone is best-effort: sockets
// that end in TIME_WAIT hand their state to a separate timewait mini-socket,
// so the original struct sock may never see a traced TCP_CLOSE.)
//
// The emitted record layout MUST stay byte-for-byte in sync with the Go decoder
// in internal/decode/decode.go (59 bytes, packed).
//
// A second, independent program (handle_dns_ingress) attaches as cgroup_skb
// ingress to the root cgroup v2 and copies the payload of every UDP packet
// from source port 53 delivered to a local socket — in any pod's network
// namespace, since cgroup programs follow the receiving socket's cgroup, not
// the netns — into the dns_events ring buffer. Userspace parses the DNS answer
// and caches IP -> hostname so external destinations get a name instead of a
// bare address. It only observes: it always returns 1 (pass). Its record
// layout MUST stay in sync with internal/decode/dns.go (2 + 512 bytes, packed).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7
#define IPPROTO_UDP_NUM 17
#define DNS_PORT 53
// DNS_MAX_PAYLOAD caps the copied DNS message. Classic UDP DNS is <= 512
// bytes; larger (EDNS0) answers are truncated and parsed best-effort.
#define DNS_MAX_PAYLOAD 512
// DNS_HEADER_LEN is the fixed DNS header; shorter payloads cannot be DNS.
#define DNS_HEADER_LEN 12

char LICENSE[] SEC("license") = "GPL";

// conn_event mirrors the Go wire format exactly. __attribute__((packed))
// guarantees no compiler padding so the 59-byte layout is stable.
struct conn_event {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport; // network byte order
	__u16 dport; // network byte order
	__u8 family;
	__u8 protocol;
	__u32 pid; // host byte order
	char comm[16];
	// outbound is 1 when this socket was initiated locally (the tcp_connect
	// fentry recorded it) and 0 for accepted/inbound sockets. Userspace uses
	// it to drop the reversed server-side record of in-cluster calls without
	// relying on ephemeral-port heuristics.
	__u8 outbound;
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
// initiated the connection. Populated by the tcp_connect fentry, consumed and
// freed by the state-change tracepoint at ESTABLISHED, and freed on TCP_CLOSE
// for connections that never establish. With only in-flight connects held, the
// map stays small; LRU is a safety net, evicting the oldest if it ever fills —
// degrading gracefully to no-PID (which resolves to the node/IP identity)
// rather than failing.
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
// the PID/comm here are the real client owner. It is an fentry (BTF) program
// rather than a kprobe: fentry derives its arguments from BTF, so it compiles
// arch-neutrally (bpfel) — a kprobe would need PT_REGS_PARM1, which requires a
// concrete __TARGET_ARCH and breaks the single multi-arch object. BTF is
// already a hard dependency (CO-RE reads /sys/kernel/btf).
SEC("fentry/tcp_connect")
int BPF_PROG(handle_tcp_connect, struct sock *sk)
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

	// Free the pid_by_sock entry when a socket closes without having reached
	// ESTABLISHED (failed/refused connects); established connections free
	// their entry when it is consumed below. LRU remains as a safety net.
	if (ctx->newstate == TCP_CLOSE) {
		bpf_map_delete_elem(&pid_by_sock, &sk);
		return 0;
	}

	// Only care about connections reaching ESTABLISHED.
	if (ctx->newstate != TCP_ESTABLISHED)
		return 0;

	// Consume the pid_by_sock entry up front, before any early return below
	// (unsupported family, ring-buffer full): its only job is to carry the
	// connecting task's identity from tcp_connect to this transition, and
	// ESTABLISHED fires exactly once per connection. Deleting here — not just
	// at TCP_CLOSE, which sockets ending in TIME_WAIT may never fire for
	// their struct sock — bounds an entry's lifetime to the
	// connect->established window, so it always belongs to a live socket
	// whose address cannot be reused. A leaked entry keyed by a freed sk
	// address could otherwise hit on an unrelated ACCEPTED socket reusing the
	// slab address, tagging it outbound with a stale pid/comm and laundering
	// a mirrored server-side record past userspace's reversed-duplicate
	// filter as a phantom edge carrying the caller's ephemeral port.
	struct pid_info info = {};
	__u8 have_info = 0;
	struct pid_info *p = bpf_map_lookup_elem(&pid_by_sock, &sk);
	if (p) {
		info.pid = p->pid;
		__builtin_memcpy(info.comm, p->comm, sizeof(info.comm));
		have_info = 1;
	}
	bpf_map_delete_elem(&pid_by_sock, &sk); // no-op for accepted sockets

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

	// Attach the connecting task's identity and mark the record outbound.
	// have_info=0 means an accepted/inbound socket (no local tcp_connect) or,
	// rarely, an LRU eviction: pid=0/comm="" signals "no process context" to
	// the resolver, and outbound=0 lets userspace orient the record
	// caller->callee and drop it when the caller is in-cluster — the
	// canonical edge is emitted on the caller's node — while keeping
	// external->inbound edges, for which this record is the only capture.
	if (have_info) {
		e->pid = info.pid;
		__builtin_memcpy(e->comm, info.comm, sizeof(e->comm));
		e->outbound = 1;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// dns_event carries one raw DNS message to userspace. len is the number of
// valid payload bytes (host byte order); the rest of payload is unspecified.
struct dns_event {
	__u16 len;
	__u8 payload[DNS_MAX_PAYLOAD];
} __attribute__((packed));

// Ring buffer carrying DNS messages to userspace (128 KiB), separate from
// events so a burst of DNS traffic never crowds out connection records.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 1024);
} dns_events SEC(".maps");

// Force BTF emission of the DNS event type for userspace/bpf2go.
struct dns_event *unused_dns_event __attribute__((unused));

// handle_dns_ingress copies DNS responses (UDP from source port 53) delivered
// to any socket under the attached cgroup. In cgroup_skb programs skb data
// starts at the network header. IPv6 extension headers are not walked: DNS
// responses do not carry them in practice. It always passes the packet.
SEC("cgroup_skb/ingress")
int handle_dns_ingress(struct __sk_buff *skb)
{
	__u8 vihl;
	if (bpf_skb_load_bytes(skb, 0, &vihl, 1) < 0)
		return 1;

	__u32 l4off;
	__u8 proto;
	if ((vihl >> 4) == 4) {
		l4off = (__u32)(vihl & 0x0f) * 4;
		if (l4off < 20)
			return 1;
		if (bpf_skb_load_bytes(skb, 9, &proto, 1) < 0)
			return 1;
	} else if ((vihl >> 4) == 6) {
		l4off = 40;
		if (bpf_skb_load_bytes(skb, 6, &proto, 1) < 0)
			return 1;
	} else {
		return 1;
	}
	if (proto != IPPROTO_UDP_NUM)
		return 1;

	__be16 sport;
	if (bpf_skb_load_bytes(skb, l4off, &sport, sizeof(sport)) < 0)
		return 1;
	if (sport != bpf_htons(DNS_PORT))
		return 1;

	__u32 off = l4off + 8; // UDP header
	if (skb->len <= off)
		return 1;
	__u32 len = skb->len - off;
	if (len > DNS_MAX_PAYLOAD)
		len = DNS_MAX_PAYLOAD;
	if (len < DNS_HEADER_LEN)
		return 1;

	struct dns_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
	if (!e)
		return 1;

	// Re-derive the bound right before the helper call so the verifier sees
	// 0 < n <= sizeof(payload) on the register passed as the size. The mask
	// is a no-op on the value (len is already <= 512) but gives the verifier
	// an unsigned [0, 1023] range that the compare narrows. It is inline asm
	// on a 64-bit value because clang otherwise folds the mask and the
	// compare away (it knows len's range) and checks a zero-extended copy,
	// leaving the size register unbounded: "R4 min value is negative".
	__u64 n = len;
	asm volatile("%[n] &= 0x3ff" : [n] "+r"(n));
	if (n == 0 || n > DNS_MAX_PAYLOAD) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}
	if (bpf_skb_load_bytes(skb, off, e->payload, n) < 0) {
		bpf_ringbuf_discard(e, 0);
		return 1;
	}
	e->len = (__u16)n;
	bpf_ringbuf_submit(e, 0);
	return 1;
}
