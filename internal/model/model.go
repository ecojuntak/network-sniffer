// Package model holds the pure domain types shared across the sniffer
// pipeline: raw connection events, resolved workloads and the service-call
// record that becomes a log line. It has no external dependencies so it can
// be compiled and unit-tested on any platform.
package model

import (
	"fmt"
	"net/netip"
	"strings"
)

// Protocol is the L4 protocol number as reported by the kernel (IP protocol).
type Protocol uint8

// Common L4 protocol numbers (see /etc/protocols).
const (
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
	ProtocolSCTP Protocol = 132
)

// String returns the lowercase protocol name, or "proto-<n>" when unknown.
func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolSCTP:
		return "sctp"
	default:
		return fmt.Sprintf("proto-%d", uint8(p))
	}
}

// recognizedL7 is the set of application-layer protocol tokens the sniffer
// reports. It mirrors Istio's protocol-selection vocabulary (appProtocol values
// and port-name prefixes). Tokens outside this set — e.g. a port named
// "metrics" or "admin" — are treated as unknown and fall back to the L4 name,
// so operational port names never masquerade as protocols.
var recognizedL7 = map[string]struct{}{
	"http":     {},
	"http2":    {},
	"https":    {},
	"grpc":     {},
	"grpc-web": {},
	"tcp":      {},
	"tls":      {},
	"mongo":    {},
	"mysql":    {},
	"redis":    {},
	"udp":      {},
}

// NormalizeL7 derives the application-layer protocol of a service port from its
// Kubernetes metadata, following the same rules Istio uses. appProtocol takes
// precedence when set; otherwise the port name's prefix before the first "-" is
// used (Istio's `<protocol>[-<suffix>]` convention, e.g. "grpc", "http-web").
// The result is lowercased and validated against recognizedL7; an unrecognized
// or empty input returns "" so callers fall back to the L4 protocol.
func NormalizeL7(appProtocol, portName string) string {
	token := strings.ToLower(strings.TrimSpace(appProtocol))
	if token == "" {
		name := strings.ToLower(strings.TrimSpace(portName))
		token, _, _ = strings.Cut(name, "-")
	}
	if _, ok := recognizedL7[token]; ok {
		return token
	}
	return ""
}

// ConnectionEvent is one connection observed by the eBPF probe. Addresses are
// decoded into netip.Addr; ports are host-order uint16.
type ConnectionEvent struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
	// PID and Comm identify the local process; useful for local-side
	// resolution fallback and debugging. May be zero/empty.
	PID  uint32
	Comm string
	// Outbound reports whether the connection was initiated locally (the
	// tcp_connect fentry recorded the socket). False means an accepted /
	// inbound socket — the server-side half of the two-sided capture.
	Outbound bool
}

// IsLoopback reports whether either endpoint is a loopback address
// (127.0.0.0/8 or ::1). Loopback traffic is intra-pod (or host-local) and
// carries no cross-workload dependency, so the pipeline drops it: the pod-IP
// cache cannot attribute it (loopback is never a pod IP and exists in every
// network namespace).
func (e ConnectionEvent) IsLoopback() bool {
	return e.SrcIP.IsLoopback() || e.DstIP.IsLoopback()
}

// IsSelfEdge reports whether both endpoints are the same address. Such traffic
// is a workload talking to itself over its own IP (e.g. a host-network pod like
// node-exporter scraped by a host-network prometheus on the same node: both
// ends carry the node IP). It carries no cross-workload dependency, so the
// pipeline drops it for the same reason as loopback. This filter is address-,
// not range-based on purpose: on clusters whose VPC CIDR is itself CGNAT
// (100.64.0.0/10), pod IPs and node IPs share that range, so a range filter
// would drop legitimate pod-to-pod edges — only src == dst is safe to drop.
func (e ConnectionEvent) IsSelfEdge() bool {
	return e.SrcIP.Unmap() == e.DstIP.Unmap()
}

// awsReservedPrefix is the fd00:ec2::/32 ULA range AWS reserves for EC2
// internal service endpoints (Instance Metadata Service fd00:ec2::254,
// VPC DNS fd00:ec2::253, Amazon Time Sync fd00:ec2::123, ...). These are
// infrastructure endpoints reachable from every instance, not cluster
// workloads, so they carry no cross-workload dependency worth logging.
var awsReservedPrefix = netip.MustParsePrefix("fd00:ec2::/32")

// IsAWSReserved reports whether either endpoint is in the AWS-reserved
// fd00:ec2::/32 range. Such traffic is host-to-infrastructure (metadata,
// DNS, NTP) and is dropped by the pipeline for the same reason as loopback:
// it has no resolvable workload identity and no cross-workload meaning.
func (e ConnectionEvent) IsAWSReserved() bool {
	return awsReservedPrefix.Contains(e.SrcIP) || awsReservedPrefix.Contains(e.DstIP)
}

// IsLinkLocal reports whether either endpoint is a link-local unicast address
// (IPv4 169.254.0.0/16 or IPv6 fe80::/10). This covers the cloud Instance
// Metadata Service (IMDS) at 169.254.169.254 — the IPv4 twin of the
// fd00:ec2:: endpoints — plus other link-local infrastructure. Such peers are
// node-local infrastructure, not cluster workloads, so the pipeline drops them
// for the same reason as loopback and the AWS-reserved range.
func (e ConnectionEvent) IsLinkLocal() bool {
	return e.SrcIP.IsLinkLocalUnicast() || e.DstIP.IsLinkLocalUnicast()
}

// Canonical returns the event in caller->callee orientation. Outbound records
// already are: the local end initiated the connection, so the destination is
// the remote service. Accepted-side records arrive mirrored — the local
// (server) address and listening port occupy the source fields, the caller's
// address and ephemeral source port the destination fields — so the tuples are
// swapped: the caller becomes the source and the destination port becomes the
// server's actual listening port. That makes kept external->in-cluster edges
// correctly oriented and collapsible by dedup (one edge per caller, not one
// per connection).
//
// The Outbound flag is left untouched: it records which half of the connection
// was observed locally and drives IsReversedDuplicate. PID/Comm are zero on
// accepted-side records (no local process context for a remote caller), so
// nothing is lost in the swap.
func (e ConnectionEvent) Canonical() ConnectionEvent {
	if e.Outbound {
		return e
	}
	e.SrcIP, e.DstIP = e.DstIP, e.SrcIP
	e.SrcPort, e.DstPort = e.DstPort, e.SrcPort
	return e
}

// IsReversedDuplicate reports whether the event is the server-side half of the
// tracepoint's two-sided capture of a call whose canonical caller->callee edge
// is observed elsewhere. The `inet_sock_set_state` tracepoint fires for BOTH
// ends of every connection: the locally-initiated side is marked Outbound (the
// tcp_connect fentry recorded the socket) and is the canonical edge; the
// accepted side is a reversed duplicate. Pass the Canonical() event and its
// resolved source, i.e. the original caller.
//
// The reversed record is dropped when the caller resolves to an in-cluster
// identity — a pod workload or a node — because the caller's own node emits
// the canonical edge. It is kept when the caller is external: out-of-cluster
// callers never execute a traced tcp_connect, so the accepted-side record is
// the only capture of external -> in-cluster traffic.
//
// Deciding on the caller (not on the local endpoint) is what makes the rule
// robust: the local side of an accepted socket can fail to resolve — e.g. a
// host-network / hostPort service reached via the node's public IP, or an
// informer cache gap — and a local-side check would then leak the mirrored
// record through as a phantom edge "<caller-workload> receives traffic on an
// ephemeral port".
//
// This replaces the former ephemeral-destination-port heuristic (drop when
// dstPort >= 32768), which broke on nodes with a custom
// net.ipv4.ip_local_port_range: with a range starting below 32768 (observed
// 1037-32730 on EKS nodes tuned to avoid the NodePort range), client source
// ports fell under the threshold and reversed records leaked through as
// phantom inbound edges — e.g. a CronJob's outbound calls appearing as
// hundreds of inbound edges to the CronJob on ever-changing ports.
func (e ConnectionEvent) IsReversedDuplicate(source Workload) bool {
	return !e.Outbound && !source.IsExternal()
}

// Workload identifies a kubernetes workload (the top-level owner of a pod,
// e.g. a Deployment or Argo Rollout), or an out-of-cluster peer.
type Workload struct {
	Name      string
	Namespace string
	// Kind is the workload kind ("Deployment", "StatefulSet", "Rollout",
	// "DaemonSet", ...) or KindExternal for peers with no cluster identity.
	Kind string
}

// KindExternal marks a peer that could not be mapped to a cluster workload
// (traffic leaving/entering the cluster).
const KindExternal = "external"

// KindServiceEntry marks a peer resolved to an Istio ServiceEntry by one of its
// VIPs (a user-specified spec address or an auto-allocated 240.240.0.0/16
// address). The workload Name is the ServiceEntry host (e.g. an RDS endpoint),
// giving external dependencies a stable name instead of a bare IP.
const KindServiceEntry = "ServiceEntry"

// KindNode marks a peer resolved to a cluster Node by its InternalIP rather
// than to a pod-owned workload. Host-network processes (node-exporter,
// kube-proxy, CNI agents, the sniffer itself) and node-level daemons source
// traffic from the node IP, which no pod owns; this gives them the node's name
// instead of a bare IP. Multiple host-network pods share one node IP, so this
// is a node-level identity, not a per-pod one.
const KindNode = "node"

// IsExternal reports whether the workload is an out-of-cluster peer.
func (w Workload) IsExternal() bool { return w.Kind == KindExternal }

// ServiceCall is the enriched, log-ready record of one source workload calling
// a destination workload on a given port and protocol.
type ServiceCall struct {
	Source       Workload
	Dest         Workload
	DestPort     uint16
	DestProtocol Protocol
	// DestAppProtocol is the resolved L7 protocol of the destination port
	// ("http", "grpc", ...) derived from the Kubernetes Service/EndpointSlice
	// port metadata. Empty when unknown; consumers fall back to DestProtocol.
	DestAppProtocol string
}
