// Package model holds the pure domain types shared across the sniffer
// pipeline: raw connection events, resolved workloads and the service-call
// record that becomes a log line. It has no external dependencies so it can
// be compiled and unit-tested on any platform.
package model

import (
	"fmt"
	"net/netip"
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

// IsExternal reports whether the workload is an out-of-cluster peer.
func (w Workload) IsExternal() bool { return w.Kind == KindExternal }

// ServiceCall is the enriched, log-ready record of one source workload calling
// a destination workload on a given port and protocol.
type ServiceCall struct {
	Source       Workload
	Dest         Workload
	DestPort     uint16
	DestProtocol Protocol
}
