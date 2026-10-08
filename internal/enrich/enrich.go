// Package enrich joins a raw connection event with the workload resolver to
// produce a log-ready ServiceCall.
package enrich

import (
	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// Enrich resolves the source and destination workloads for an event and
// returns the corresponding ServiceCall. Unknown peers become external
// workloads via resolver.WorkloadForIP, so the result is always fully
// populated.
//
// The source is resolved by IP first. When that yields only a Node or external
// identity — the signature of host-network / node-level traffic sharing the
// node IP — and the event carries the connecting process's pod UID (resolved
// on the node from the process's cgroup), the UID is looked up in uids to
// recover the exact owning pod. The UID path never overrides a concrete pod-IP
// match, guarding against a stale UID displacing good data. A nil uids store
// disables the UID path.
// Destinations are remote, so they are always IP-resolved.
//
// The destination's application-layer protocol is resolved from the Kubernetes
// Service / EndpointSlice port metadata via ports; a nil ports store, or a
// destination whose port declares no recognized protocol, leaves
// DestAppProtocol empty and callers fall back to the L4 protocol.
func Enrich(ev model.ConnectionEvent, store resolver.Store, uids resolver.UIDStore, ports resolver.PortStore) model.ServiceCall {
	source := resolver.WorkloadForIP(store, ev.SrcIP)
	if uids != nil && ev.SrcPodUID != "" && (source.Kind == model.KindNode || source.IsExternal()) {
		if w, ok := uids.LookupUID(ev.SrcPodUID); ok {
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
