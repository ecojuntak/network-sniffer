package enrich

import (
	"net/netip"
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

func TestEnrichBothKnown(t *testing.T) {
	c := resolver.NewCache()
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	c.Upsert(src, model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"})
	c.Upsert(dst, model.Workload{Name: "checkout", Namespace: "shop", Kind: "Rollout"})

	ev := model.ConnectionEvent{SrcIP: src, DstIP: dst, DstPort: 8080, Protocol: model.ProtocolTCP}
	sc := Enrich(ev, c)

	if sc.Source.Name != "frontend" || sc.Source.Namespace != "shop" {
		t.Errorf("source = %+v", sc.Source)
	}
	if sc.Dest.Name != "checkout" || sc.Dest.Namespace != "shop" {
		t.Errorf("dest = %+v", sc.Dest)
	}
	if sc.DestPort != 8080 || sc.DestProtocol != model.ProtocolTCP {
		t.Errorf("port/proto = %d/%v", sc.DestPort, sc.DestProtocol)
	}
}

// A call leaving the cluster: source is a known workload, destination is not
// in the cache and must be marked external.
func TestEnrichExternalDestination(t *testing.T) {
	c := resolver.NewCache()
	src := netip.MustParseAddr("10.0.0.1")
	c.Upsert(src, model.Workload{Name: "worker", Namespace: "jobs", Kind: "Deployment"})

	ev := model.ConnectionEvent{
		SrcIP:    src,
		DstIP:    netip.MustParseAddr("34.117.59.81"),
		DstPort:  443,
		Protocol: model.ProtocolTCP,
	}
	sc := Enrich(ev, c)

	if sc.Source.Name != "worker" {
		t.Errorf("source = %+v, want worker", sc.Source)
	}
	if !sc.Dest.IsExternal() || sc.Dest.Name != "34.117.59.81" {
		t.Errorf("dest = %+v, want external IP", sc.Dest)
	}
	if sc.DestPort != 443 {
		t.Errorf("port = %d, want 443", sc.DestPort)
	}
}

func TestEnrichBothUnknown(t *testing.T) {
	c := resolver.NewCache()
	ev := model.ConnectionEvent{
		SrcIP:    netip.MustParseAddr("1.1.1.1"),
		DstIP:    netip.MustParseAddr("2.2.2.2"),
		DstPort:  53,
		Protocol: model.ProtocolUDP,
	}
	sc := Enrich(ev, c)
	if !sc.Source.IsExternal() || !sc.Dest.IsExternal() {
		t.Fatalf("expected both external, got src=%+v dst=%+v", sc.Source, sc.Dest)
	}
}
