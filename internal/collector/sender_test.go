package collector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
)

// fakeClient records delivered batches and fails the first failN calls.
type fakeClient struct {
	mu    sync.Mutex
	failN int
	calls int
	got   []*snifferv1.ReportRequest
}

func (f *fakeClient) Report(_ context.Context, req *snifferv1.ReportRequest, _ ...grpc.CallOption) (*snifferv1.ReportResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("unavailable")
	}
	f.got = append(f.got, req)
	return &snifferv1.ReportResponse{}, nil
}

func (f *fakeClient) delivered() []*snifferv1.ReportRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*snifferv1.ReportRequest(nil), f.got...)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func batch(n int) []*snifferv1.FlowRecord {
	b := make([]*snifferv1.FlowRecord, n)
	for i := range b {
		b[i] = &snifferv1.FlowRecord{DstPort: uint32(i)}
	}
	return b
}

func TestSenderEnqueueDropsOldestWhenFull(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	s := NewSender(&fakeClient{}, "node-a", 2, time.Second, discard(), m)

	s.Enqueue(batch(1))
	s.Enqueue(batch(2))
	s.Enqueue(batch(3)) // evicts the 1-record batch

	if got := testutil.ToFloat64(m.RecordsDropped); got != 1 {
		t.Fatalf("dropped = %v, want 1", got)
	}
	if first := <-s.queue; len(first) != 2 {
		t.Fatalf("oldest remaining batch has %d records, want 2", len(first))
	}
}

func TestSenderRetriesUntilDelivered(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	c := &fakeClient{failN: 2}
	s := NewSender(c, "node-a", 10, time.Second, discard(), m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	s.Enqueue(batch(5))

	deadline := time.Now().Add(5 * time.Second)
	for len(c.delivered()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("batch not delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := c.delivered()[0]
	if got.GetNodeName() != "node-a" || len(got.GetRecords()) != 5 {
		t.Fatalf("delivered %+v", got)
	}
	if v := testutil.ToFloat64(m.ReportErrors); v != 2 {
		t.Errorf("report errors = %v, want 2", v)
	}
	if v := testutil.ToFloat64(m.RecordsSent); v != 5 {
		t.Errorf("records sent = %v, want 5", v)
	}
}
