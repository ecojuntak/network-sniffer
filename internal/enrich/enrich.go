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
func Enrich(ev model.ConnectionEvent, store resolver.Store) model.ServiceCall {
	return model.ServiceCall{
		Source:       resolver.WorkloadForIP(store, ev.SrcIP),
		Dest:         resolver.WorkloadForIP(store, ev.DstIP),
		DestPort:     ev.DstPort,
		DestProtocol: ev.Protocol,
	}
}
