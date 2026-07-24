// Package enrich joins a raw connection event with the workload resolver to
// produce a log-ready ServiceCall.
package enrich

import (
	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// PIDStore resolves the workload owning a local process by its PID. It upgrades
// source resolution for host-network / node-level traffic, whose IP is the node
// IP and therefore only reachable as a Node (or external) via the IP index.
// resolver.ProcResolver satisfies it. A nil PIDStore disables the PID path.
type PIDStore interface {
	LookupPID(pid uint32) (model.Workload, bool)
}

// Enrich resolves the source and destination workloads for an event and
// returns the corresponding ServiceCall. Unknown peers become external
// workloads via resolver.WorkloadForIP, so the result is always fully
// populated.
//
// The source is resolved by IP first. When that yields only a Node or external
// identity — the signature of host-network / node-level traffic sharing the
// node IP — and a PID store is supplied, the connecting process's PID is used
// to recover the exact owning pod. The PID path never overrides a concrete
// pod-IP match, guarding against a stale or reused PID displacing good data.
// Destinations are remote, so they are always IP-resolved.
//
// The destination's application-layer protocol is resolved from the Kubernetes
// Service / EndpointSlice port metadata via ports; a nil ports store, or a
// destination whose port declares no recognized protocol, leaves
// DestAppProtocol empty and callers fall back to the L4 protocol.
func Enrich(ev model.ConnectionEvent, store resolver.Store, pids PIDStore, ports resolver.PortStore) model.ServiceCall {
	source := resolver.WorkloadForIP(store, ev.SrcIP)
	if pids != nil && (source.Kind == model.KindNode || source.IsExternal()) {
		if w, ok := pids.LookupPID(ev.PID); ok {
			source = w
		}
	}
	var l7 string
	if ports != nil {
		l7, _ = ports.LookupPort(ev.DstIP, ev.DstPort)
	}
	return model.ServiceCall{
		Source:          source,
		Dest:            resolver.WorkloadForIP(store, ev.DstIP),
		DestPort:        ev.DstPort,
		DestProtocol:    ev.Protocol,
		DestAppProtocol: l7,
	}
}
