package collector

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/ecojuntak/network-sniffer/internal/bpf"
	"github.com/ecojuntak/network-sniffer/internal/decode"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// pidCacheTTL bounds how long a PID -> pod UID result is reused. It saves a
// procfs read per connection for chatty processes; PID reuse within this
// window is negligible.
const pidCacheTTL = 10 * time.Second

// Source yields raw probe events. bpf.Loader satisfies it; Read must return
// bpf.ErrClosed once the source is closed.
type Source interface {
	Read() ([]byte, error)
}

// Config tunes the collector.
type Config struct {
	// ProcRoot is the host procfs mount used for PID -> pod UID resolution.
	ProcRoot string
	// FlushInterval is how often aggregated flows are handed to the sender.
	FlushInterval time.Duration
	// MaxBatch caps the records per Report call; reaching it in the
	// aggregator also triggers an early flush.
	MaxBatch int
}

// Collector runs the node-local pipeline: read -> decode -> canonical ->
// filter -> pod UID -> aggregate -> batch.
type Collector struct {
	cfg    Config
	agg    *Aggregator
	sender *Sender
	log    *slog.Logger
	m      *Metrics

	pidUIDs      map[uint32]string
	pidUIDsSince time.Time
}

// New returns a Collector handing batches to sender.
func New(cfg Config, sender *Sender, log *slog.Logger, m *Metrics) *Collector {
	return &Collector{
		cfg:     cfg,
		agg:     NewAggregator(),
		sender:  sender,
		log:     log,
		m:       m,
		pidUIDs: make(map[uint32]string),
	}
}

// Run reads events from src until it is closed or ctx is cancelled. Closing
// src on cancellation is the caller's job, since Read blocks.
func (c *Collector) Run(ctx context.Context, src Source) error {
	go c.flushLoop(ctx)
	for {
		raw, err := src.Read()
		if errors.Is(err, bpf.ErrClosed) {
			return ctx.Err()
		}
		if err != nil {
			c.m.Events.WithLabelValues(resultReadError).Inc()
			c.log.Warn("read event", slog.Any("err", err))
			continue
		}
		c.handle(raw, time.Now())
	}
}

// handle runs one raw event through the node-local pipeline.
func (c *Collector) handle(raw []byte, now time.Time) {
	ev, err := decode.Decode(raw)
	if err != nil {
		c.m.Events.WithLabelValues(resultDecodeError).Inc()
		c.log.Warn("decode event", slog.Any("err", err))
		return
	}

	// Canonical orients every record caller->callee: accepted-side records
	// arrive mirrored and are swapped, so the destination port is the
	// service's listening port. See model.go.
	ev = ev.Canonical()

	// Loopback, self, AWS-reserved and link-local traffic carry no
	// cross-workload dependency. Dropping them here needs no cluster state
	// and keeps them off the wire.
	if ev.IsLoopback() || ev.IsSelfEdge() || ev.IsAWSReserved() || ev.IsLinkLocal() {
		c.m.Events.WithLabelValues(resultFiltered).Inc()
		return
	}

	// The connecting process's pod is only discoverable here, from its
	// cgroup in the host procfs. The processor uses it to attribute
	// host-network sources that share the node IP.
	if ev.Outbound {
		ev.SrcPodUID = c.podUID(ev.PID, now)
	}

	c.m.Events.WithLabelValues(resultAccepted).Inc()
	if c.agg.Add(ev, now) >= c.cfg.MaxBatch {
		c.flush()
	}
}

// podUID resolves pid to its pod UID through a short-lived cache.
func (c *Collector) podUID(pid uint32, now time.Time) string {
	if pid == 0 {
		return ""
	}
	if now.Sub(c.pidUIDsSince) >= pidCacheTTL {
		clear(c.pidUIDs)
		c.pidUIDsSince = now
	}
	if uid, ok := c.pidUIDs[pid]; ok {
		return uid
	}
	uid, _ := resolver.PodUIDForPID(c.cfg.ProcRoot, pid)
	c.pidUIDs[pid] = uid
	return uid
}

// flushLoop flushes aggregated flows every FlushInterval until ctx is done.
func (c *Collector) flushLoop(ctx context.Context) {
	t := time.NewTicker(c.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.flush()
		}
	}
}

// flush drains the aggregator into batches of at most MaxBatch records.
func (c *Collector) flush() {
	records := c.agg.Drain()
	for len(records) > 0 {
		n := min(len(records), c.cfg.MaxBatch)
		c.sender.Enqueue(records[:n:n])
		records = records[n:]
	}
}
