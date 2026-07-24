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

// EphemeralPortMin is the lowest port in the Linux default ephemeral range
// (net.ipv4.ip_local_port_range = 32768-60999). Client sockets draw their
// source port from this range; listening services almost always sit below it.
const EphemeralPortMin uint16 = 32768

// HasEphemeralDestPort reports whether the destination port is in the
// ephemeral range. The `inet_sock_set_state` tracepoint fires for BOTH ends of
// every connection, so a single call A->B:svc yields two events: the client
// side (dst = B's service port) and the server side (dst = A's ephemeral port).
// The client side is the canonical caller->callee edge and is always captured
// (both sockets share a node for same-node pairs; cluster-wide the caller's own
// node sees it). The server-side record is a reversed duplicate identifiable by
// its ephemeral destination port, so the pipeline drops it — de-duplicating the
// two-sided capture without correlating socket pairs.
//
// Limitation: a service that listens on an ephemeral-range port is dropped too.
// Rare in practice; revisit with a configurable threshold if it bites.
func (e ConnectionEvent) HasEphemeralDestPort() bool {
	return e.DstPort >= EphemeralPortMin
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
