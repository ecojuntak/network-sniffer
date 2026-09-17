//go:build linux

package resolver

import (
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

// seedService adds a Service directly into the Service informer's indexer,
// mirroring seed()'s approach for Pods/ReplicaSets/Jobs/Nodes.
func seedService(t *testing.T, c *Controller, svc *corev1.Service) {
	t.Helper()
	if err := c.factory.Core().V1().Services().Informer().GetIndexer().Add(svc); err != nil {
		t.Fatalf("seed service: %v", err)
	}
}

// onEndpointSlice indexes both the pod-IP:port L7 entries and, via the
// Service the slice's kubernetes.io/service-name label points at, a
// ClusterIP -> pod IP mapping so pre-DNAT traffic to the ClusterIP resolves
// through the normal pod-IP cache lookup.
func TestOnEndpointSliceIndexesClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "checkout")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.5"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "172.20.0.10",
			ClusterIPs: []string{"172.20.0.10"},
			Ports:      []corev1.ServicePort{{Name: "grpc", Port: 8080}},
		},
	}
	seedService(t, c, svc)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "checkout"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}
	c.onEndpointSlice(es)

	want := model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}
	assertWorkload(t, c, "172.20.0.10", want)
	assertWorkload(t, c, "10.0.1.5", want)
}

// Handles the Service-added-before-EndpointSlice race: a Service update
// re-derives ClusterIP mappings from its already-synced EndpointSlices.
func TestOnServiceUpdateIndexesClusterIPForRace(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-abc", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "api")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.9"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	// The EndpointSlice arrives (and is indexed) before the Service exists in
	// the lister — indexClusterIPsFromEndpointSlice's Service lookup misses,
	// so no ClusterIP mapping is created yet.
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "api"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.9"}}},
	}
	if err := c.factory.Discovery().V1().EndpointSlices().Informer().GetIndexer().Add(es); err != nil {
		t.Fatalf("seed endpointslice: %v", err)
	}
	c.onEndpointSlice(es)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("172.20.0.50")); ok {
		t.Fatal("ClusterIP resolved before its Service existed")
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: "172.20.0.50", ClusterIPs: []string{"172.20.0.50"}},
	}
	seedService(t, c, svc)
	c.onServiceUpdate(nil, svc)

	want := model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"}
	assertWorkload(t, c, "172.20.0.50", want)
}

// Re-indexing on an EndpointSlice update points the ClusterIP at whichever
// pod is now backing it (Upsert overwrites, no explicit old-entry deletion
// needed).
func TestOnEndpointSliceUpdateClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-1", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "checkout")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.5"},
	}
	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-2", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "checkout")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.6"},
	}
	seed(t, c, pod1, pod2)
	c.onPod(pod1)
	c.onPod(pod2)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: "172.20.0.10", ClusterIPs: []string{"172.20.0.10"}},
	}
	seedService(t, c, svc)

	oldES := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "checkout"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}
	newES := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "checkout"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.6"}}},
	}

	c.onEndpointSlice(oldES)
	c.onEndpointSliceUpdate(oldES, newES)

	want := model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}
	assertWorkload(t, c, "172.20.0.10", want)
}

func TestOnEndpointSliceDeleteClusterIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "checkout")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.5"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: "172.20.0.10", ClusterIPs: []string{"172.20.0.10"}},
	}
	seedService(t, c, svc)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "checkout"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}
	c.onEndpointSlice(es)

	want := model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}
	assertWorkload(t, c, "172.20.0.10", want)

	c.onEndpointSliceDelete(es)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("172.20.0.10")); ok {
		t.Error("ClusterIP still cached after EndpointSlice delete")
	}
}

// A headless Service has no ClusterIP, so onEndpointSlice must add nothing
// beyond the pod IP that onPod already indexed.
func TestOnEndpointSliceClusterIPHeadlessService(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "headless-abc", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("StatefulSet", "headless")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.5"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone},
	}
	seedService(t, c, svc)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "headless-abc", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "headless"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}

	before := c.cache.Len()
	c.onEndpointSlice(es)
	after := c.cache.Len()
	if after != before {
		t.Errorf("headless service added ClusterIP entries: before=%d after=%d", before, after)
	}
}

// An EndpointSlice without the kubernetes.io/service-name label cannot be
// tied to a Service, so no ClusterIP mapping is attempted.
func TestOnEndpointSliceClusterIPNoServiceLabel(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-abc", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "test")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.5"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-abc", Namespace: "default",
			Labels: map[string]string{},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}

	before := c.cache.Len()
	c.onEndpointSlice(es)
	after := c.cache.Len()
	if after != before {
		t.Errorf("EndpointSlice without service label added entries: before=%d after=%d", before, after)
	}
}

// reindexAllClusterIPs re-derives every Service's ClusterIP mapping from its
// EndpointSlices' current pod IPs; safe to call more than once (idempotent).
func TestReindexAllClusterIPsIdempotent(t *testing.T) {
	c := NewController(fake.NewSimpleClientset(), nil)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "web")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.2.5"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec:       corev1.ServiceSpec{ClusterIP: "172.20.1.1", ClusterIPs: []string{"172.20.1.1"}},
	}
	seedService(t, c, svc)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "web"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.2.5"}}},
	}
	if err := c.factory.Discovery().V1().EndpointSlices().Informer().GetIndexer().Add(es); err != nil {
		t.Fatalf("seed endpointslice: %v", err)
	}

	want := model.Workload{Name: "web", Namespace: "shop", Kind: "Deployment"}

	c.reindexAllClusterIPs()
	assertWorkload(t, c, "172.20.1.1", want)

	c.reindexAllClusterIPs()
	assertWorkload(t, c, "172.20.1.1", want)
}
