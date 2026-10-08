//go:build linux

package resolver

import (
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func assertWorkload(t *testing.T, c *Controller, ip string, want model.Workload) {
	t.Helper()
	got, ok := c.cache.LookupIP(netip.MustParseAddr(ip))
	if !ok {
		t.Errorf("LookupIP(%s): no entry, want %+v", ip, want)
		return
	}
	if got != want {
		t.Errorf("LookupIP(%s) = %+v, want %+v", ip, got, want)
	}
}

func assertNoWorkload(t *testing.T, c *Controller, ip string) {
	t.Helper()
	if got, ok := c.cache.LookupIP(netip.MustParseAddr(ip)); ok {
		t.Errorf("LookupIP(%s) = %+v, want no entry", ip, got)
	}
}

// trimmed runs obj through the informer transform, as client-go does before
// storing it, so tests see exactly what production handlers see.
func trimmed[T any](t *testing.T, obj T) T {
	t.Helper()
	out, err := trimObject(obj)
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	return out.(T)
}

// seedService adds a (trimmed) Service directly into the Service informer's
// indexer, mirroring seed()'s approach for Pods/ReplicaSets/Jobs/Nodes.
func seedService(t *testing.T, c *Controller, svc *corev1.Service) *corev1.Service {
	t.Helper()
	svc = trimmed(t, svc)
	if err := c.factory.Core().V1().Services().Informer().GetIndexer().Add(svc); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	return svc
}

// seedSlice adds or replaces a (trimmed) EndpointSlice in the informer's
// indexer. client-go updates the indexer before dispatching handlers, so tests
// seed first and then invoke the handler.
func seedSlice(t *testing.T, c *Controller, es *discoveryv1.EndpointSlice) *discoveryv1.EndpointSlice {
	t.Helper()
	es = trimmed(t, es)
	if err := c.factory.Discovery().V1().EndpointSlices().Informer().GetIndexer().Update(es); err != nil {
		t.Fatalf("seed endpointslice: %v", err)
	}
	return es
}

func unseedSlice(t *testing.T, c *Controller, es *discoveryv1.EndpointSlice) {
	t.Helper()
	if err := c.factory.Discovery().V1().EndpointSlices().Informer().GetIndexer().Delete(es); err != nil {
		t.Fatalf("unseed endpointslice: %v", err)
	}
}

func unseedService(t *testing.T, c *Controller, svc *corev1.Service) {
	t.Helper()
	if err := c.factory.Core().V1().Services().Informer().GetIndexer().Delete(svc); err != nil {
		t.Fatalf("unseed service: %v", err)
	}
}

// addPod seeds a pod owned by the given controller and indexes it.
func addPod(t *testing.T, c *Controller, ns, name, ownerKind, owner, ip string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{ctrlRef(ownerKind, owner)},
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
	seed(t, c, pod)
	c.onPod(pod)
}

func newService(ns, name string, clusterIPs ...string) *corev1.Service {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	if len(clusterIPs) > 0 {
		svc.Spec.ClusterIP = clusterIPs[0]
		svc.Spec.ClusterIPs = clusterIPs
	}
	return svc
}

// newSlice builds an EndpointSlice for service carrying the usual bloat (extra
// labels) that trimObject must strip without losing the service-name label.
func newSlice(ns, name, service string, addrs ...string) *discoveryv1.EndpointSlice {
	labels := map[string]string{"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}
	if service != "" {
		labels[endpointSliceServiceNameLabel] = service
	}
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: addrs}},
	}
}

var checkout = model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}

// onEndpointSlice maps the backing Service's ClusterIP to the workload behind
// its endpoints, so pre-DNAT traffic to the ClusterIP resolves. The slice goes
// through trimObject first, guarding against the transform dropping the
// service-name label.
func TestOnEndpointSliceIndexesClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-abc", "Deployment", "checkout", "10.0.1.5")
	seedService(t, c, newService("shop", "checkout", "172.20.0.10"))

	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.5")))

	assertWorkload(t, c, "172.20.0.10", checkout)
	assertWorkload(t, c, "10.0.1.5", checkout)
}

// A Service added after its EndpointSlices synced maps its ClusterIP from its
// own add handler, without waiting for a later slice event.
func TestOnServiceAddIndexesClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "api-abc", "Deployment", "api", "10.0.1.9")

	// The slice arrives before the Service exists in the lister: no mapping yet.
	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "api-abc", "api", "10.0.1.9")))
	assertNoWorkload(t, c, "172.20.0.50")

	c.onService(seedService(t, c, newService("shop", "api", "172.20.0.50")))

	assertWorkload(t, c, "172.20.0.50", model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"})
}

// A Service update re-derives the mapping from its already-synced slices.
func TestOnServiceUpdateIndexesClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "api-abc", "Deployment", "api", "10.0.1.9")
	seedSlice(t, c, newSlice("shop", "api-abc", "api", "10.0.1.9"))

	svc := seedService(t, c, newService("shop", "api", "172.20.0.50"))
	c.onServiceUpdate(nil, svc)

	assertWorkload(t, c, "172.20.0.50", model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"})
}

// A Service update that drops its ClusterIP (e.g. type -> ExternalName) evicts
// the old mapping.
func TestOnServiceUpdateEvictsDroppedClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-abc", "Deployment", "checkout", "10.0.1.5")
	oldSvc := seedService(t, c, newService("shop", "checkout", "172.20.0.10"))
	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.5")))
	assertWorkload(t, c, "172.20.0.10", checkout)

	newSvc := seedService(t, c, newService("shop", "checkout"))
	c.onServiceUpdate(oldSvc, newSvc)

	assertNoWorkload(t, c, "172.20.0.10")
}

// Deleting a Service evicts its ClusterIP instead of leaving a stale identity.
func TestOnServiceDeleteEvictsClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-abc", "Deployment", "checkout", "10.0.1.5")
	svc := seedService(t, c, newService("shop", "checkout", "172.20.0.10"))
	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.5")))
	assertWorkload(t, c, "172.20.0.10", checkout)

	unseedService(t, c, svc)
	c.onServiceDelete(cache.DeletedFinalStateUnknown{Key: "shop/x", Obj: svc})

	assertNoWorkload(t, c, "172.20.0.10")
	assertWorkload(t, c, "10.0.1.5", checkout)
}

// An EndpointSlice update keeps the ClusterIP pointed at whatever now backs it.
func TestOnEndpointSliceUpdateClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-1", "Deployment", "checkout", "10.0.1.5")
	addPod(t, c, "shop", "other-1", "Deployment", "other", "10.0.1.6")
	seedService(t, c, newService("shop", "checkout", "172.20.0.10"))

	oldES := seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.5"))
	c.onEndpointSlice(oldES)
	assertWorkload(t, c, "172.20.0.10", checkout)

	newES := seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.6"))
	c.onEndpointSliceUpdate(oldES, newES)

	assertWorkload(t, c, "172.20.0.10", model.Workload{Name: "other", Namespace: "shop", Kind: "Deployment"})
}

// Deleting the last slice of a Service evicts its ClusterIP.
func TestOnEndpointSliceDeleteLastSliceEvictsClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-abc", "Deployment", "checkout", "10.0.1.5")
	seedService(t, c, newService("shop", "checkout", "172.20.0.10"))
	es := seedSlice(t, c, newSlice("shop", "checkout-abc", "checkout", "10.0.1.5"))
	c.onEndpointSlice(es)
	assertWorkload(t, c, "172.20.0.10", checkout)

	unseedSlice(t, c, es)
	c.onEndpointSliceDelete(es)

	assertNoWorkload(t, c, "172.20.0.10")
}

// Deleting one of several slices keeps the ClusterIP mapped via the rest.
func TestOnEndpointSliceDeleteKeepsClusterIPWhileOtherSlicesRemain(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-1", "Deployment", "checkout", "10.0.1.5")
	addPod(t, c, "shop", "checkout-2", "Deployment", "checkout", "10.0.1.6")
	seedService(t, c, newService("shop", "checkout", "172.20.0.10"))
	es1 := seedSlice(t, c, newSlice("shop", "checkout-a", "checkout", "10.0.1.5"))
	c.onEndpointSlice(es1)
	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-b", "checkout", "10.0.1.6")))

	unseedSlice(t, c, es1)
	c.onEndpointSliceDelete(cache.DeletedFinalStateUnknown{Key: "shop/x", Obj: es1})

	assertWorkload(t, c, "172.20.0.10", checkout)
}

// A Service whose endpoints span two workloads resolves to a Service identity
// rather than whichever workload happened to be indexed last.
func TestClusterIPMultipleWorkloadsResolvesToService(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "checkout-1", "Deployment", "checkout", "10.0.1.5")
	addPod(t, c, "shop", "checkout-canary-1", "Deployment", "checkout-canary", "10.0.1.7")
	seedService(t, c, newService("shop", "checkout", "172.20.0.10"))

	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-a", "checkout", "10.0.1.5")))
	assertWorkload(t, c, "172.20.0.10", checkout)

	c.onEndpointSlice(seedSlice(t, c, newSlice("shop", "checkout-b", "checkout", "10.0.1.7")))
	assertWorkload(t, c, "172.20.0.10", model.Workload{Name: "checkout", Namespace: "shop", Kind: model.KindService})
}

// A headless Service has no ClusterIP, so onEndpointSlice must add nothing
// beyond the pod IP that onPod already indexed.
func TestOnEndpointSliceClusterIPHeadlessService(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "default", "headless-abc", "StatefulSet", "headless", "10.0.1.5")
	seedService(t, c, newService("default", "headless", corev1.ClusterIPNone))

	before := c.cache.Len()
	c.onEndpointSlice(seedSlice(t, c, newSlice("default", "headless-abc", "headless", "10.0.1.5")))
	if after := c.cache.Len(); after != before {
		t.Errorf("headless service added ClusterIP entries: before=%d after=%d", before, after)
	}
}

// An EndpointSlice without the kubernetes.io/service-name label cannot be
// tied to a Service, so no ClusterIP mapping is attempted.
func TestOnEndpointSliceClusterIPNoServiceLabel(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "default", "test-abc", "Deployment", "test", "10.0.1.5")

	before := c.cache.Len()
	c.onEndpointSlice(seedSlice(t, c, newSlice("default", "test-abc", "", "10.0.1.5")))
	if after := c.cache.Len(); after != before {
		t.Errorf("EndpointSlice without service label added entries: before=%d after=%d", before, after)
	}
}

// reindexAllClusterIPs re-derives every Service's ClusterIP mapping from its
// EndpointSlices' current pod IPs; safe to call more than once (idempotent).
func TestReindexAllClusterIPsIdempotent(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)
	addPod(t, c, "shop", "web-abc", "Deployment", "web", "10.0.2.5")
	seedService(t, c, newService("shop", "web", "172.20.1.1"))
	seedSlice(t, c, newSlice("shop", "web-abc", "web", "10.0.2.5"))

	want := model.Workload{Name: "web", Namespace: "shop", Kind: "Deployment"}

	c.reindexAllClusterIPs()
	assertWorkload(t, c, "172.20.1.1", want)

	c.reindexAllClusterIPs()
	assertWorkload(t, c, "172.20.1.1", want)
}
