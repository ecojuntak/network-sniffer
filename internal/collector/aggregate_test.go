package collector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func TestAggregatorCollapsesEphemeralPorts(t *testing.T) {
	a := NewAggregator()
	t0 := time.Unix(100, 0)
	base := model.ConnectionEvent{
		SrcIP:     netip.MustParseAddr("10.0.0.1"),
		DstIP:     netip.MustParseAddr("10.0.0.2"),
		DstPort:   8080,
		Protocol:  model.ProtocolTCP,
		Outbound:  true,
		Comm:      "curl",
		SrcPodUID: "uid-1",
	}
	for i := range 3 {
		ev := base
		ev.SrcPort = uint16(50000 + i)
		a.Add(ev, t0.Add(time.Duration(i)*time.Second))
	}

	recs := a.Drain()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.GetCount() != 3 {
		t.Errorf("count = %d, want 3", r.GetCount())
	}
	if r.GetFirstSeenUnixNano() != t0.UnixNano() || r.GetLastSeenUnixNano() != t0.Add(2*time.Second).UnixNano() {
		t.Errorf("first/last = %d/%d", r.GetFirstSeenUnixNano(), r.GetLastSeenUnixNano())
	}
	if r.GetDstPort() != 8080 || r.GetComm() != "curl" || r.GetSrcPodUid() != "uid-1" || !r.GetOutbound() {
		t.Errorf("unexpected record %+v", r)
	}
	if got, _ := netip.AddrFromSlice(r.GetSrcIp()); got != base.SrcIP {
		t.Errorf("src = %v, want %v", got, base.SrcIP)
	}
}

func TestAggregatorKeepsDistinctFlows(t *testing.T) {
	a := NewAggregator()
	now := time.Now()
	ev := model.ConnectionEvent{
		SrcIP:    netip.MustParseAddr("10.0.0.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		DstPort:  80,
		Protocol: model.ProtocolTCP,
		Outbound: true,
	}
	a.Add(ev, now)
	other := ev
	other.Outbound = false
	a.Add(other, now)
	other = ev
	other.DstPort = 81
	if n := a.Add(other, now); n != 3 {
		t.Fatalf("Add reported %d flows, want 3", n)
	}
}

func TestAggregatorDrainResets(t *testing.T) {
	a := NewAggregator()
	a.Add(model.ConnectionEvent{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2")}, time.Now())
	if got := len(a.Drain()); got != 1 {
		t.Fatalf("first drain = %d, want 1", got)
	}
	if got := len(a.Drain()); got != 0 {
		t.Fatalf("second drain = %d, want 0", got)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
