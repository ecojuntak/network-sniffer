package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
	"github.com/ecojuntak/network-sniffer/internal/collector"
	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/ignore"
	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

var (
	frontendIP = netip.MustParseAddr("10.0.0.1")
	checkoutIP = netip.MustParseAddr("10.0.0.2")
	nodeIP     = netip.MustParseAddr("100.90.106.4")
	frontend   = model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"}
	checkout   = model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}
	exporter   = model.Workload{Name: "node-exporter", Namespace: "monitoring", Kind: "DaemonSet"}
)

const exporterUID = "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f"

type fixture struct {
	srv *Server
	m   *Metrics
	out *bytes.Buffer
}

func newFixture(t *testing.T, ignores ...string) fixture {
	t.Helper()
	cache := resolver.NewCache()
	cache.Upsert(frontendIP, frontend)
	cache.Upsert(checkoutIP, checkout)
	cache.Upsert(nodeIP, model.Workload{Name: "ip-100-90-106-4", Kind: model.KindNode})
	cache.UpsertUID(exporterUID, exporter)

	matcher, err := ignore.Compile(ignores)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	m := NewMetrics(prometheus.NewRegistry())
	p := NewPipeline(cache, matcher, dedup.New(time.Minute), emit.New(&out), m)
	return fixture{srv: NewServer(p, m), m: m, out: &out}
}

// edges parses the emitted JSON lines into "src -> dst:port" strings.
func edges(t *testing.T, out *bytes.Buffer) []string {
	t.Helper()
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad JSON line %q: %v", line, err)
		}
		got = append(got, fmt.Sprintf("%s -> %s:%v",
			rec[emit.FieldSourceWorkload], rec[emit.FieldDestWorkload], rec[emit.FieldDestPort]))
	}
	return got
}

func record(src, dst netip.Addr, port uint32, outbound bool, uid string) *snifferv1.FlowRecord {
	return &snifferv1.FlowRecord{
		SrcIp:     src.AsSlice(),
		DstIp:     dst.AsSlice(),
		DstPort:   port,
		Protocol:  uint32(model.ProtocolTCP),
		Outbound:  outbound,
		SrcPodUid: uid,
		Count:     1,
	}
}

func report(t *testing.T, f fixture, recs ...*snifferv1.FlowRecord) {
	t.Helper()
	if _, err := f.srv.Report(context.Background(), &snifferv1.ReportRequest{NodeName: "n", Records: recs}); err != nil {
		t.Fatalf("Report: %v", err)
	}
}

func TestReportEnrichesAndEmits(t *testing.T) {
	f := newFixture(t)
	report(t, f, record(frontendIP, checkoutIP, 8080, true, ""))

	got := edges(t, f.out)
	if len(got) != 1 || got[0] != "frontend -> checkout:8080" {
		t.Fatalf("edges = %v", got)
	}
}

func TestReportPodUIDUpgradesNodeSource(t *testing.T) {
	f := newFixture(t)
	report(t, f, record(nodeIP, checkoutIP, 9100, true, exporterUID))

	got := edges(t, f.out)
	if len(got) != 1 || got[0] != "node-exporter -> checkout:9100" {
		t.Fatalf("edges = %v", got)
	}
}

func TestReportDropsReversedDuplicate(t *testing.T) {
	f := newFixture(t)
	// Accepted-side half of an in-cluster call: the caller's node reports it.
	report(t, f, record(frontendIP, checkoutIP, 8080, false, ""))

	if got := edges(t, f.out); len(got) != 0 {
		t.Fatalf("edges = %v, want none", got)
	}
	if v := testutil.ToFloat64(f.m.Records.WithLabelValues(resultReversedDuplicate)); v != 1 {
		t.Fatalf("reversed duplicates = %v, want 1", v)
	}
}

func TestReportKeepsExternalCaller(t *testing.T) {
	f := newFixture(t)
	report(t, f, record(netip.MustParseAddr("203.0.113.9"), checkoutIP, 443, false, ""))

	got := edges(t, f.out)
	if len(got) != 1 || got[0] != "203.0.113.9 -> checkout:443" {
		t.Fatalf("edges = %v", got)
	}
}

func TestReportIgnoresAndDedups(t *testing.T) {
	f := newFixture(t, "monitoring/*")
	report(t, f,
		record(frontendIP, checkoutIP, 8080, true, ""),
		record(frontendIP, checkoutIP, 8080, true, ""),      // duplicate
		record(nodeIP, checkoutIP, 9100, true, exporterUID), // ignored
	)

	if got := edges(t, f.out); len(got) != 1 {
		t.Fatalf("edges = %v, want 1", got)
	}
	if v := testutil.ToFloat64(f.m.Records.WithLabelValues(resultDuplicate)); v != 1 {
		t.Errorf("duplicates = %v, want 1", v)
	}
	if v := testutil.ToFloat64(f.m.Records.WithLabelValues(resultIgnored)); v != 1 {
		t.Errorf("ignored = %v, want 1", v)
	}
}

func TestReportSkipsInvalidRecords(t *testing.T) {
	f := newFixture(t)
	report(t, f,
		&snifferv1.FlowRecord{SrcIp: []byte{1, 2, 3}, DstIp: checkoutIP.AsSlice(), DstPort: 80},
		&snifferv1.FlowRecord{SrcIp: frontendIP.AsSlice(), DstIp: checkoutIP.AsSlice(), DstPort: 70000},
		record(frontendIP, checkoutIP, 8080, true, ""),
	)

	if v := testutil.ToFloat64(f.m.Records.WithLabelValues(resultInvalid)); v != 2 {
		t.Fatalf("invalid = %v, want 2", v)
	}
	if got := edges(t, f.out); len(got) != 1 {
		t.Fatalf("edges = %v, want 1", got)
	}
}

func TestToEventUnmapsIPv4InIPv6(t *testing.T) {
	mapped := netip.AddrFrom16(frontendIP.As16())
	ev, ok := toEvent(record(mapped, checkoutIP, 80, true, ""))
	if !ok || ev.SrcIP != frontendIP {
		t.Fatalf("toEvent = %+v, %v; want unmapped %v", ev, ok, frontendIP)
	}
}

// TestCollectorToProcessorOverGRPC runs the collector's aggregator and sender
// against a real gRPC server over an in-memory listener.
func TestCollectorToProcessorOverGRPC(t *testing.T) {
	f := newFixture(t)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	snifferv1.RegisterProcessorServiceServer(gs, f.srv)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cm := collector.NewMetrics(prometheus.NewRegistry())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sender := collector.NewSender(snifferv1.NewProcessorServiceClient(conn), "node-a", 10, time.Second, logger, cm)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = sender.Run(ctx) }()

	agg := collector.NewAggregator()
	now := time.Now()
	for sport := range uint16(10) {
		agg.Add(model.ConnectionEvent{
			SrcIP: frontendIP, DstIP: checkoutIP, SrcPort: 40000 + sport, DstPort: 8080,
			Protocol: model.ProtocolTCP, Outbound: true,
		}, now)
	}
	sender.Enqueue(agg.Drain())

	deadline := time.Now().Add(5 * time.Second)
	for testutil.ToFloat64(cm.RecordsSent) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("records never delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := edges(t, f.out)
	if len(got) != 1 || got[0] != "frontend -> checkout:8080" {
		t.Fatalf("edges = %v", got)
	}
}
