package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ecojuntak/network-sniffer/internal/decode"
	"github.com/ecojuntak/network-sniffer/internal/model"
)

// rawEvent builds a raw IPv4 probe record in the layout decode expects.
func rawEvent(src, dst [4]byte, sport, dport uint16, pid uint32, outbound bool) []byte {
	b := make([]byte, decode.EventSize)
	copy(b[0:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[32:], sport)
	binary.BigEndian.PutUint16(b[34:], dport)
	b[36] = 2 // AF_INET
	b[37] = uint8(model.ProtocolTCP)
	binary.LittleEndian.PutUint32(b[38:], pid)
	if outbound {
		b[58] = 1
	}
	return b
}

func newTestCollector(t *testing.T, procRoot string) (*Collector, *Metrics) {
	t.Helper()
	m := NewMetrics(prometheus.NewRegistry())
	s := NewSender(&fakeClient{}, "node-a", 10, time.Second, discard(), m)
	c := New(Config{ProcRoot: procRoot, FlushInterval: time.Second, MaxBatch: 100}, s, discard(), m)
	return c, m
}

func TestCollectorFiltersNodeLocalNoise(t *testing.T) {
	c, m := newTestCollector(t, t.TempDir())
	now := time.Now()
	c.handle(rawEvent([4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, 1, 2, 0, true), now)
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{169, 254, 169, 254}, 1, 80, 0, true), now)

	if got := testutil.ToFloat64(m.Events.WithLabelValues(resultFiltered)); got != 2 {
		t.Fatalf("filtered = %v, want 2", got)
	}
	if got := len(c.agg.Drain()); got != 0 {
		t.Fatalf("aggregated %d flows, want 0", got)
	}
}

func TestCollectorCanonicalizesAndAttachesPodUID(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods.slice/kubepods-pod3f8e3c4d_1a2b_4c5d_8e9f_0a1b2c3d4e5f.slice/x.scope"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}

	c, _ := newTestCollector(t, root)
	now := time.Now()
	// Outbound: caller 10.0.0.1:50000 -> 10.0.0.2:8080, PID 4242.
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 50000, 8080, 4242, true), now)
	// Accepted side arrives mirrored: server 10.0.0.2:8080, caller 10.0.0.3:41000.
	c.handle(rawEvent([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 3}, 8080, 41000, 0, false), now)

	recs := c.agg.Drain()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for _, r := range recs {
		if r.GetDstPort() != 8080 {
			t.Errorf("dst port = %d, want 8080 (canonical)", r.GetDstPort())
		}
		switch r.GetOutbound() {
		case true:
			if r.GetSrcPodUid() != "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f" {
				t.Errorf("outbound pod uid = %q", r.GetSrcPodUid())
			}
		case false:
			if r.GetSrcPodUid() != "" {
				t.Errorf("accepted-side record must carry no pod uid, got %q", r.GetSrcPodUid())
			}
		}
	}
}

func TestCollectorFlushSplitsBatches(t *testing.T) {
	c, _ := newTestCollector(t, t.TempDir())
	c.cfg.MaxBatch = 2
	now := time.Now()
	for port := range uint16(5) {
		c.agg.Add(model.ConnectionEvent{
			SrcIP:   mustAddr("10.0.0.1"),
			DstIP:   mustAddr("10.0.0.2"),
			DstPort: 1000 + port,
		}, now)
	}
	c.flush()

	var sizes []int
	for len(c.sender.queue) > 0 {
		sizes = append(sizes, len(<-c.sender.queue))
	}
	if len(sizes) != 3 || sizes[0] != 2 || sizes[1] != 2 || sizes[2] != 1 {
		t.Fatalf("batch sizes = %v, want [2 2 1]", sizes)
	}
}
