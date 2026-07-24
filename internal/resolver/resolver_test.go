package resolver

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func TestCacheUpsertLookupDelete(t *testing.T) {
	c := NewCache()
	ip := netip.MustParseAddr("10.0.0.1")
	w := model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"}

	if _, ok := c.LookupIP(ip); ok {
		t.Fatal("empty cache returned a hit")
	}

	c.Upsert(ip, w)
	got, ok := c.LookupIP(ip)
	if !ok || got != w {
		t.Fatalf("LookupIP = %+v,%v want %+v,true", got, ok, w)
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}

	// Upsert replaces.
	w2 := model.Workload{Name: "api-v2", Namespace: "shop", Kind: "Rollout"}
	c.Upsert(ip, w2)
	if got, _ := c.LookupIP(ip); got != w2 {
		t.Fatalf("after replace LookupIP = %+v, want %+v", got, w2)
	}
	if c.Len() != 1 {
		t.Fatalf("Len after replace = %d, want 1", c.Len())
	}

	c.Delete(ip)
	if _, ok := c.LookupIP(ip); ok {
		t.Fatal("LookupIP returned hit after Delete")
	}
	c.Delete(ip) // deleting absent IP is a no-op
}

// A v4-mapped v6 address and its v4 form must resolve to the same entry.
func TestCacheUnmapEquivalence(t *testing.T) {
	c := NewCache()
	v4 := netip.MustParseAddr("10.0.0.9")
	mapped := netip.MustParseAddr("::ffff:10.0.0.9")
	w := model.Workload{Name: "svc", Namespace: "ns", Kind: "Deployment"}

	c.Upsert(mapped, w)
	if got, ok := c.LookupIP(v4); !ok || got != w {
		t.Fatalf("v4 lookup of mapped upsert = %+v,%v want %+v,true", got, ok, w)
	}
}

func TestWorkloadForIP(t *testing.T) {
	c := NewCache()
	known := netip.MustParseAddr("10.0.0.1")
	c.Upsert(known, model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"})

	if got := WorkloadForIP(c, known); got.Name != "api" || got.IsExternal() {
		t.Fatalf("known WorkloadForIP = %+v, want api/not-external", got)
	}

	ext := netip.MustParseAddr("8.8.8.8")
	got := WorkloadForIP(c, ext)
	if !got.IsExternal() {
		t.Fatalf("unknown IP not marked external: %+v", got)
	}
	if got.Name != "8.8.8.8" {
		t.Fatalf("external Name = %q, want the IP string", got.Name)
	}
	if got.Namespace != "" {
		t.Fatalf("external Namespace = %q, want empty", got.Namespace)
	}
}

// fakeOwners is a map-backed OwnerLookup: key "Kind/name" -> controlling owner.
type fakeOwners map[string]struct{ kind, name string }

func (f fakeOwners) GetController(kind, _ /*namespace*/, name string) (string, string, bool) {
	o, ok := f[kind+"/"+name]
	if !ok {
		return "", "", false
	}
	return o.kind, o.name, true
}

func TestResolveTopOwnerDeployment(t *testing.T) {
	owners := fakeOwners{
		"Pod/api-7d8f9-abcde":  {"ReplicaSet", "api-7d8f9"},
		"ReplicaSet/api-7d8f9": {"Deployment", "api"},
	}
	got := ResolveTopOwner("Pod", "shop", "api-7d8f9-abcde", owners)
	want := model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"}
	if got != want {
		t.Fatalf("ResolveTopOwner = %+v, want %+v", got, want)
	}
}

func TestResolveTopOwnerRollout(t *testing.T) {
	owners := fakeOwners{
		"Pod/web-abc-xyz":    {"ReplicaSet", "web-abc"},
		"ReplicaSet/web-abc": {"Rollout", "web"},
	}
	got := ResolveTopOwner("Pod", "store", "web-abc-xyz", owners)
	want := model.Workload{Name: "web", Namespace: "store", Kind: "Rollout"}
	if got != want {
		t.Fatalf("ResolveTopOwner = %+v, want %+v", got, want)
	}
}

// A bare pod (no controller, e.g. a static or manually-created pod) resolves
// to itself.
func TestResolveTopOwnerNoController(t *testing.T) {
	got := ResolveTopOwner("Pod", "kube-system", "standalone", fakeOwners{})
	want := model.Workload{Name: "standalone", Namespace: "kube-system", Kind: "Pod"}
	if got != want {
		t.Fatalf("ResolveTopOwner = %+v, want %+v", got, want)
	}
}

// A cyclic ownership graph must terminate at the depth bound rather than loop
// forever.
func TestResolveTopOwnerCycleBounded(t *testing.T) {
	owners := fakeOwners{
		"A/x": {"B", "y"},
		"B/y": {"A", "x"},
	}
	done := make(chan model.Workload, 1)
	go func() { done <- ResolveTopOwner("A", "ns", "x", owners) }()

	select {
	case <-done:
		// Terminated within the bound — success.
	default:
		// Give the goroutine a moment; a hang here means the bound failed.
	}
	got := <-done
	if got.Namespace != "ns" {
		t.Fatalf("namespace lost across walk: %+v", got)
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := NewCache()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(n)})
			c.Upsert(ip, model.Workload{Name: "w", Namespace: "ns", Kind: "Deployment"})
			c.LookupIP(ip)
		}(i)
	}
	wg.Wait()
	if c.Len() != 50 {
		t.Fatalf("Len = %d, want 50", c.Len())
	}
}

func TestCachePortUpsertLookupDelete(t *testing.T) {
	c := NewCache()
	ip := netip.MustParseAddr("10.0.0.2")

	if _, ok := c.LookupPort(ip, 8080); ok {
		t.Fatal("empty cache returned a port entry")
	}

	c.UpsertPort(ip, 8080, "grpc")
	if l7, ok := c.LookupPort(ip, 8080); !ok || l7 != "grpc" {
		t.Fatalf("LookupPort = %q,%v want grpc,true", l7, ok)
	}
	// A different port on the same IP is a distinct key.
	if _, ok := c.LookupPort(ip, 9090); ok {
		t.Fatal("unrelated port resolved")
	}

	c.DeletePort(ip, 8080)
	if _, ok := c.LookupPort(ip, 8080); ok {
		t.Fatal("port entry survived delete")
	}
}

// UpsertPort with an empty protocol clears any existing entry rather than
// indexing a blank protocol.
func TestCachePortUpsertEmptyClears(t *testing.T) {
	c := NewCache()
	ip := netip.MustParseAddr("10.0.0.2")
	c.UpsertPort(ip, 8080, "http")
	c.UpsertPort(ip, 8080, "")
	if _, ok := c.LookupPort(ip, 8080); ok {
		t.Fatal("empty upsert did not clear the entry")
	}
}

// A v4-mapped v6 destination keys identically to its v4 form.
func TestCachePortUnmapsAddresses(t *testing.T) {
	c := NewCache()
	c.UpsertPort(netip.MustParseAddr("10.0.0.2"), 8080, "grpc")
	mapped := netip.MustParseAddr("::ffff:10.0.0.2")
	if l7, ok := c.LookupPort(mapped, 8080); !ok || l7 != "grpc" {
		t.Fatalf("mapped lookup = %q,%v want grpc,true", l7, ok)
	}
}
