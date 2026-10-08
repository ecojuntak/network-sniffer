// Package collector is the node-local half of the sniffer. It reads raw
// connection events from the eBPF probe, drops node-local noise, attaches the
// connecting pod's UID (only resolvable on the node), folds connection churn
// into flow records and ships them in batches to the central processor. It
// holds no Kubernetes state: identity resolution happens in the processor.
package collector

import (
	"net/netip"
	"sync"
	"time"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
	"github.com/ecojuntak/network-sniffer/internal/model"
)

// flowKey is the aggregation identity of a canonical connection. The caller's
// ephemeral source port is deliberately absent so repeated connections between
// the same endpoints collapse into one record.
type flowKey struct {
	src, dst netip.Addr
	dstPort  uint16
	proto    model.Protocol
	outbound bool
	podUID   string
}

type flow struct {
	comm        string
	count       uint32
	first, last time.Time
}

// Aggregator folds canonical connection events into flow records until they
// are drained. It is safe for concurrent use.
type Aggregator struct {
	mu    sync.Mutex
	flows map[flowKey]*flow
}

// NewAggregator returns an empty Aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{flows: make(map[flowKey]*flow)}
}

// Add records one canonical event observed at now and returns the number of
// distinct flows currently held.
func (a *Aggregator) Add(ev model.ConnectionEvent, now time.Time) int {
	k := flowKey{
		src:      ev.SrcIP,
		dst:      ev.DstIP,
		dstPort:  ev.DstPort,
		proto:    ev.Protocol,
		outbound: ev.Outbound,
		podUID:   ev.SrcPodUID,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	f, ok := a.flows[k]
	if !ok {
		f = &flow{first: now}
		a.flows[k] = f
	}
	if f.comm == "" {
		f.comm = ev.Comm
	}
	f.count++
	f.last = now
	return len(a.flows)
}

// Drain returns every held flow as a wire record and resets the aggregator.
func (a *Aggregator) Drain() []*snifferv1.FlowRecord {
	a.mu.Lock()
	flows := a.flows
	a.flows = make(map[flowKey]*flow, len(flows))
	a.mu.Unlock()

	out := make([]*snifferv1.FlowRecord, 0, len(flows))
	for k, f := range flows {
		out = append(out, &snifferv1.FlowRecord{
			SrcIp:             k.src.AsSlice(),
			DstIp:             k.dst.AsSlice(),
			DstPort:           uint32(k.dstPort),
			Protocol:          uint32(k.proto),
			Outbound:          k.outbound,
			SrcPodUid:         k.podUID,
			Comm:              f.comm,
			Count:             f.count,
			FirstSeenUnixNano: f.first.UnixNano(),
			LastSeenUnixNano:  f.last.UnixNano(),
		})
	}
	return out
}
