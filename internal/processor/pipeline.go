// Package processor is the central half of the sniffer. It receives flow
// records from every node's collector over gRPC and runs them through
// enrichment against the cluster-wide workload cache, the reversed-duplicate
// and ignore filters, dedup and emission.
package processor

import (
	"time"

	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/enrich"
	"github.com/ecojuntak/network-sniffer/internal/ignore"
	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// Cache is the workload state the pipeline enriches against. resolver.Cache
// satisfies it.
type Cache interface {
	resolver.Store
	resolver.UIDStore
	resolver.PortStore
}

// Pipeline turns canonical connection events into emitted service-call edges.
// It is safe for concurrent use.
type Pipeline struct {
	cache   Cache
	matcher *ignore.Matcher
	deduper *dedup.Deduper
	out     *emit.Logger
	m       *Metrics
	now     func() time.Time
}

// NewPipeline wires the pipeline stages.
func NewPipeline(cache Cache, matcher *ignore.Matcher, deduper *dedup.Deduper, out *emit.Logger, m *Metrics) *Pipeline {
	return &Pipeline{cache: cache, matcher: matcher, deduper: deduper, out: out, m: m, now: time.Now}
}

// Handle enriches one canonical event and emits it unless filtered or
// suppressed.
func (p *Pipeline) Handle(ev model.ConnectionEvent) {
	sc := enrich.Enrich(ev, p.cache, p.cache, p.cache)

	// IsReversedDuplicate drops the accepted-side half of the tracepoint's
	// two-sided capture when the caller is in-cluster: the caller's own
	// node reports the canonical caller->callee edge. External callers are
	// kept — the accepted-side record is the only capture of
	// external -> in-cluster traffic. See model.go.
	if ev.IsReversedDuplicate(sc.Source) {
		p.m.Records.WithLabelValues(resultReversedDuplicate).Inc()
		return
	}
	if p.matcher.ShouldIgnoreCall(sc) {
		p.m.Records.WithLabelValues(resultIgnored).Inc()
		return
	}
	if !p.deduper.Allow(sc, p.now()) {
		p.m.Records.WithLabelValues(resultDuplicate).Inc()
		return
	}
	p.m.Records.WithLabelValues(resultEmitted).Inc()
	p.out.Log(sc)
}
