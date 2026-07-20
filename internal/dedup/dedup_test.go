package dedup

import (
	"testing"
	"time"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func call(destName string, port uint16) model.ServiceCall {
	return model.ServiceCall{
		Source:       model.Workload{Name: "src", Namespace: "ns", Kind: "Deployment"},
		Dest:         model.Workload{Name: destName, Namespace: "ns", Kind: "Deployment"},
		DestPort:     port,
		DestProtocol: model.ProtocolTCP,
	}
}

func TestAllowFirstThenSuppress(t *testing.T) {
	d := New(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	sc := call("api", 8080)

	if !d.Allow(sc, base) {
		t.Fatal("first sighting should be allowed")
	}
	if d.Allow(sc, base.Add(30*time.Second)) {
		t.Fatal("duplicate within window should be suppressed")
	}
}

func TestAllowAfterWindow(t *testing.T) {
	d := New(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	sc := call("api", 8080)

	d.Allow(sc, base)
	if !d.Allow(sc, base.Add(time.Minute)) {
		t.Fatal("sighting at exactly the window boundary should be allowed")
	}
	// The boundary sighting resets the clock; an immediate repeat is suppressed.
	if d.Allow(sc, base.Add(time.Minute+time.Second)) {
		t.Fatal("repeat right after re-allow should be suppressed")
	}
}

func TestAllowDistinctEdges(t *testing.T) {
	d := New(time.Minute)
	base := time.Unix(1_700_000_000, 0)

	if !d.Allow(call("api", 8080), base) {
		t.Fatal("edge A should be allowed")
	}
	if !d.Allow(call("api", 9090), base) {
		t.Fatal("different port is a distinct edge and should be allowed")
	}
	if !d.Allow(call("db", 8080), base) {
		t.Fatal("different dest is a distinct edge and should be allowed")
	}
}

func TestZeroWindowDisablesDedup(t *testing.T) {
	d := New(0)
	base := time.Unix(1_700_000_000, 0)
	sc := call("api", 8080)
	for i := range 5 {
		if !d.Allow(sc, base) {
			t.Fatalf("call %d suppressed despite disabled dedup", i)
		}
	}
}

func TestSweepEvictsExpired(t *testing.T) {
	d := New(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	d.Allow(call("api", 8080), base)
	d.Allow(call("db", 5432), base)

	if n := d.Sweep(base.Add(30 * time.Second)); n != 0 {
		t.Fatalf("Sweep evicted %d entries within window, want 0", n)
	}
	if n := d.Sweep(base.Add(2 * time.Minute)); n != 2 {
		t.Fatalf("Sweep evicted %d entries, want 2", n)
	}
	// After eviction the edge is treated as new again.
	if !d.Allow(call("api", 8080), base.Add(3*time.Minute)) {
		t.Fatal("edge should be allowed again after eviction")
	}
}

func TestSweepZeroWindowNoop(t *testing.T) {
	d := New(0)
	d.Allow(call("api", 8080), time.Unix(1_700_000_000, 0))
	if n := d.Sweep(time.Unix(1_700_009_999, 0)); n != 0 {
		t.Fatalf("Sweep with disabled dedup evicted %d, want 0", n)
	}
}
