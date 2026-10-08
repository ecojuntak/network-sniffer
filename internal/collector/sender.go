package collector

import (
	"context"
	"log/slog"
	"time"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
)

// Retry backoff bounds for failed Report calls.
const (
	minBackoff = 100 * time.Millisecond
	maxBackoff = 10 * time.Second
)

// Sender delivers record batches to the processor through a bounded queue.
// When the processor is slow or unreachable the queue fills and the oldest
// batches are dropped, so a processor outage costs data, never node memory.
type Sender struct {
	client  snifferv1.ProcessorServiceClient
	node    string
	queue   chan []*snifferv1.FlowRecord
	timeout time.Duration
	log     *slog.Logger
	m       *Metrics
	// failing is set while the processor is unreachable, so an outage logs
	// once on entry and once on recovery rather than per attempt.
	failing bool
}

// NewSender returns a Sender reporting as node, holding at most queueSize
// batches and bounding each Report call by timeout.
func NewSender(client snifferv1.ProcessorServiceClient, node string, queueSize int, timeout time.Duration, log *slog.Logger, m *Metrics) *Sender {
	return &Sender{
		client:  client,
		node:    node,
		queue:   make(chan []*snifferv1.FlowRecord, queueSize),
		timeout: timeout,
		log:     log,
		m:       m,
	}
}

// Enqueue queues a batch for delivery without blocking, evicting the oldest
// queued batch when the queue is full.
func (s *Sender) Enqueue(batch []*snifferv1.FlowRecord) {
	if len(batch) == 0 {
		return
	}
	for {
		select {
		case s.queue <- batch:
			s.m.QueueDepth.Set(float64(len(s.queue)))
			return
		default:
		}
		select {
		case old := <-s.queue:
			s.m.RecordsDropped.Add(float64(len(old)))
		default:
		}
	}
}

// Run delivers queued batches until ctx is cancelled. Each batch is retried
// with exponential backoff until it is delivered or evicted by newer data.
func (s *Sender) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch := <-s.queue:
			s.m.QueueDepth.Set(float64(len(s.queue)))
			if err := s.send(ctx, batch); err != nil {
				return err
			}
		}
	}
}

// send delivers one batch, retrying until success or ctx cancellation. It
// gives up on the batch (counting it dropped) once the queue is full, so a
// long outage keeps the freshest data instead of the oldest.
func (s *Sender) send(ctx context.Context, batch []*snifferv1.FlowRecord) error {
	req := &snifferv1.ReportRequest{NodeName: s.node, Records: batch}
	backoff := minBackoff
	for {
		callCtx, cancel := context.WithTimeout(ctx, s.timeout)
		_, err := s.client.Report(callCtx, req)
		cancel()
		if err == nil {
			s.m.RecordsSent.Add(float64(len(batch)))
			if s.failing {
				s.log.Info("processor reachable again")
				s.failing = false
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.m.ReportErrors.Inc()
		if !s.failing {
			s.log.Warn("report to processor failed, retrying", slog.Any("err", err))
			s.failing = true
		}
		if len(s.queue) == cap(s.queue) {
			s.m.RecordsDropped.Add(float64(len(batch)))
			return nil
		}

		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		backoff = min(backoff*2, maxBackoff)
	}
}
