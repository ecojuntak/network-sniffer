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
	sc := Enrich(ev, c, nil, nil)

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
	sc := Enrich(ev, c, nil, nil)

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

// fakePIDStore returns a fixed workload for a matching PID.
type fakePIDStore struct {
	pid uint32
	wl  model.Workload
}

func (f fakePIDStore) LookupPID(pid uint32) (model.Workload, bool) {
	if pid == f.pid {
		return f.wl, true
	}
	return model.Workload{}, false
}

// A host-network source resolves by IP only to the Node; the connecting PID
// upgrades it to the exact owning pod workload.
func TestEnrichPIDUpgradesNodeSource(t *testing.T) {
	c := resolver.NewCache()
	nodeIP := netip.MustParseAddr("100.90.106.4")
	dst := netip.MustParseAddr("10.0.0.2")
	c.Upsert(nodeIP, model.Workload{Name: "ip-100-90-106-4", Kind: model.KindNode})
	c.Upsert(dst, model.Workload{Name: "checkout", Namespace: "shop", Kind: "Rollout"})

	pod := model.Workload{Name: "node-exporter", Namespace: "monitoring", Kind: "DaemonSet"}
	pids := fakePIDStore{pid: 4242, wl: pod}

	ev := model.ConnectionEvent{SrcIP: nodeIP, DstIP: dst, DstPort: 9100, Protocol: model.ProtocolTCP, PID: 4242}
	sc := Enrich(ev, c, pids, nil)

	if sc.Source != pod {
		t.Fatalf("source = %+v, want %+v", sc.Source, pod)
	}
}

// An external source (unknown IP) is likewise upgraded when the PID resolves.
func TestEnrichPIDUpgradesExternalSource(t *testing.T) {
	c := resolver.NewCache()
	pod := model.Workload{Name: "kube-proxy", Namespace: "kube-system", Kind: "DaemonSet"}
	pids := fakePIDStore{pid: 10, wl: pod}

	ev := model.ConnectionEvent{
		SrcIP:    netip.MustParseAddr("100.64.1.1"),
		DstIP:    netip.MustParseAddr("10.0.0.2"),
		DstPort:  443,
		Protocol: model.ProtocolTCP,
		PID:      10,
	}
	sc := Enrich(ev, c, pids, nil)
	if sc.Source != pod {
		t.Fatalf("source = %+v, want %+v", sc.Source, pod)
	}
}

// A concrete pod-IP source must NOT be overridden by the PID path, even if the
// PID store would return something (guards against stale/reused PIDs).
func TestEnrichPIDDoesNotOverridePodIP(t *testing.T) {
	c := resolver.NewCache()
	src := netip.MustParseAddr("10.0.0.1")
	ipPod := model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"}
	c.Upsert(src, ipPod)

	pids := fakePIDStore{pid: 4242, wl: model.Workload{Name: "WRONG", Kind: "DaemonSet"}}
	ev := model.ConnectionEvent{SrcIP: src, DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 80, Protocol: model.ProtocolTCP, PID: 4242}
	sc := Enrich(ev, c, pids, nil)

	if sc.Source != ipPod {
		t.Fatalf("source = %+v, want pod-IP result %+v (PID must not override)", sc.Source, ipPod)
	}
}

// When the PID does not resolve, the Node identity from the IP index stands.
func TestEnrichPIDMissKeepsNode(t *testing.T) {
	c := resolver.NewCache()
	nodeIP := netip.MustParseAddr("100.90.106.4")
	node := model.Workload{Name: "ip-100-90-106-4", Kind: model.KindNode}
	c.Upsert(nodeIP, node)

	pids := fakePIDStore{pid: 4242, wl: model.Workload{Name: "x"}}
	ev := model.ConnectionEvent{SrcIP: nodeIP, DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 9100, Protocol: model.ProtocolTCP, PID: 999}
	sc := Enrich(ev, c, pids, nil)

	if sc.Source != node {
		t.Fatalf("source = %+v, want node %+v", sc.Source, node)
	}
}

// The destination's L7 protocol is resolved from the port store when the
// (dstIP, dstPort) endpoint declares one.
func TestEnrichResolvesAppProtocol(t *testing.T) {
	c := resolver.NewCache()
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	c.Upsert(src, model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"})
	c.Upsert(dst, model.Workload{Name: "checkout", Namespace: "shop", Kind: "Rollout"})
	c.UpsertPort(dst, 8080, "grpc")

	ev := model.ConnectionEvent{SrcIP: src, DstIP: dst, DstPort: 8080, Protocol: model.ProtocolTCP}
	sc := Enrich(ev, c, nil, c)

	if sc.DestAppProtocol != "grpc" {
		t.Errorf("app protocol = %q, want grpc", sc.DestAppProtocol)
	}
}

// An unindexed endpoint leaves DestAppProtocol empty (callers fall back to L4).
func TestEnrichUnknownAppProtocol(t *testing.T) {
	c := resolver.NewCache()
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	c.Upsert(src, model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"})

	ev := model.ConnectionEvent{SrcIP: src, DstIP: dst, DstPort: 8080, Protocol: model.ProtocolTCP}
	sc := Enrich(ev, c, nil, c)

	if sc.DestAppProtocol != "" {
		t.Errorf("app protocol = %q, want empty", sc.DestAppProtocol)
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
	sc := Enrich(ev, c, nil, nil)
	if !sc.Source.IsExternal() || !sc.Dest.IsExternal() {
		t.Fatalf("expected both external, got src=%+v dst=%+v", sc.Source, sc.Dest)
	}
}
