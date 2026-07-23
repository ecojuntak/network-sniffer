//go:build linux

package resolver

import (
	"net/netip"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clientcache "k8s.io/client-go/tools/cache"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func ctrlRef(kind, name string) metav1.OwnerReference {
	t := true
	return metav1.OwnerReference{Kind: kind, Name: name, Controller: &t}
}

// seed populates the controller's informer indexers directly (synchronously),
// avoiding informer goroutine/ordering races so the test is deterministic.
func seed(t *testing.T, c *Controller, objs ...any) {
	t.Helper()
	podIdx := c.factory.Core().V1().Pods().Informer().GetIndexer()
	rsIdx := c.factory.Apps().V1().ReplicaSets().Informer().GetIndexer()
	for _, o := range objs {
		var err error
		switch o.(type) {
		case *corev1.Pod:
			err = podIdx.Add(o)
		case *appsv1.ReplicaSet:
			err = rsIdx.Add(o)
		case *corev1.Node:
			err = c.factory.Core().V1().Nodes().Informer().GetIndexer().Add(o)
		default:
			t.Fatalf("unsupported seed object %T", o)
		}
		if err != nil {
			t.Fatalf("seed add: %v", err)
		}
	}
}

func TestControllerResolvesPodToDeployment(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())

	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: "api-7d8f9", Namespace: "shop",
		OwnerReferences: []metav1.OwnerReference{ctrlRef("Deployment", "api")},
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-7d8f9-abcde", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("ReplicaSet", "api-7d8f9")},
		},
		Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.0.0.5"}}},
	}
	seed(t, c, rs, pod)

	c.onPod(pod)

	got, ok := c.cache.LookupIP(netip.MustParseAddr("10.0.0.5"))
	if !ok {
		t.Fatal("pod IP not resolved into cache")
	}
	want := model.Workload{Name: "api", Namespace: "shop", Kind: "Deployment"}
	if got != want {
		t.Fatalf("resolved workload = %+v, want %+v", got, want)
	}
}

// A pod controlled directly by a StatefulSet (no ReplicaSet layer) resolves to
// the StatefulSet.
func TestControllerResolvesDirectController(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "db-0", Namespace: "data",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("StatefulSet", "db")},
		},
		Status: corev1.PodStatus{PodIP: "10.1.1.1"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	got, ok := c.cache.LookupIP(netip.MustParseAddr("10.1.1.1"))
	if !ok || (got != model.Workload{Name: "db", Namespace: "data", Kind: "StatefulSet"}) {
		t.Fatalf("resolved = %+v,%v want db/data/StatefulSet", got, ok)
	}
}

func TestControllerPodDelete(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-0", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("StatefulSet", "api")},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.9"},
	}
	seed(t, c, pod)
	c.onPod(pod)
	if c.cache.Len() != 1 {
		t.Fatalf("cache Len after add = %d, want 1", c.cache.Len())
	}

	c.onPodDelete(pod)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("10.0.0.9")); ok {
		t.Fatal("pod IP still cached after delete")
	}
}

// onPodDelete must handle the tombstone wrapper delivered on missed deletes.
func TestControllerPodDeleteTombstone(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("StatefulSet", "s")}},
		Status: corev1.PodStatus{PodIP: "10.2.2.2"},
	}
	seed(t, c, pod)
	c.onPod(pod)

	tomb := clientcache.DeletedFinalStateUnknown{Key: "ns/p", Obj: pod}
	c.onPodDelete(tomb)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("10.2.2.2")); ok {
		t.Fatal("pod IP still cached after tombstone delete")
	}
}

// A pod without an assigned IP must be ignored (not scheduled yet).
func TestControllerPodNoIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns"}}
	seed(t, c, pod)
	c.onPod(pod)
	if c.cache.Len() != 0 {
		t.Fatalf("cache Len = %d, want 0 for IP-less pod", c.cache.Len())
	}
}

// Host-network pods report the node IP as their pod IP; indexing them would
// attribute all node-host traffic to a single workload (phantom dest edges).
// They must be skipped.
func TestControllerSkipsHostNetworkPod(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "network-sniffer-abcde", Namespace: "canary-prober",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("DaemonSet", "network-sniffer")},
		},
		Spec:   corev1.PodSpec{HostNetwork: true},
		Status: corev1.PodStatus{PodIP: "10.20.30.40"}, // == node IP for host-network pods
	}
	seed(t, c, pod)
	c.onPod(pod)

	if c.cache.Len() != 0 {
		t.Fatalf("cache Len = %d, want 0 for host-network pod", c.cache.Len())
	}
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("10.20.30.40")); ok {
		t.Fatal("host-network pod IP (node IP) must not be cached")
	}
}

// A node's InternalIP resolves to a Node-kind workload named after the node.
// This gives host-network source traffic (node-exporter, kube-proxy, the
// sniffer itself) a stable identity instead of a bare IP.
func TestControllerResolvesNodeInternalIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "ip-100-90-106-4.eu-central-1.compute.internal"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "100.90.106.4"},
		}},
	}
	seed(t, c, node)
	c.onNode(node)

	got, ok := c.cache.LookupIP(netip.MustParseAddr("100.90.106.4"))
	if !ok {
		t.Fatal("node InternalIP not resolved into cache")
	}
	want := model.Workload{Name: "ip-100-90-106-4.eu-central-1.compute.internal", Kind: model.KindNode}
	if got != want {
		t.Fatalf("resolved workload = %+v, want %+v", got, want)
	}
}

// External and DNS node addresses must not be indexed; only InternalIP is a
// valid in-cluster source address.
func TestControllerNodeIgnoresNonInternalIP(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeExternalIP, Address: "3.4.5.6"},
			{Type: corev1.NodeInternalDNS, Address: "node-a.internal"},
			{Type: corev1.NodeHostName, Address: "node-a"},
		}},
	}
	seed(t, c, node)
	c.onNode(node)

	if c.cache.Len() != 0 {
		t.Fatalf("cache Len = %d, want 0 (no InternalIP present)", c.cache.Len())
	}
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("3.4.5.6")); ok {
		t.Fatal("node ExternalIP must not be cached")
	}
}

func TestControllerNodeDualStackIPs(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-ds"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "100.90.106.4"},
			{Type: corev1.NodeInternalIP, Address: "fd00::abcd"},
		}},
	}
	seed(t, c, node)
	c.onNode(node)

	if _, ok := c.cache.LookupIP(netip.MustParseAddr("100.90.106.4")); !ok {
		t.Error("v4 node IP not cached")
	}
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("fd00::abcd")); !ok {
		t.Error("v6 node IP not cached")
	}
}

func TestControllerNodeDelete(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-x"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "100.90.106.4"},
		}},
	}
	seed(t, c, node)
	c.onNode(node)
	if c.cache.Len() != 1 {
		t.Fatalf("cache Len after add = %d, want 1", c.cache.Len())
	}

	c.onNodeDelete(node)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("100.90.106.4")); ok {
		t.Fatal("node IP still cached after delete")
	}
}

// onNodeDelete must handle the tombstone wrapper delivered on missed deletes.
func TestControllerNodeDeleteTombstone(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-t"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: "100.90.106.5"},
		}},
	}
	seed(t, c, node)
	c.onNode(node)

	tomb := clientcache.DeletedFinalStateUnknown{Key: "node-t", Obj: node}
	c.onNodeDelete(tomb)
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("100.90.106.5")); ok {
		t.Fatal("node IP still cached after tombstone delete")
	}
}

func TestControllerDualStackIPs(t *testing.T) {
	c := NewController(fake.NewSimpleClientset())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ds", Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{ctrlRef("DaemonSet", "ds")}},
		Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.3.3.3"}, {IP: "fd00::1"}}},
	}
	seed(t, c, pod)
	c.onPod(pod)

	if _, ok := c.cache.LookupIP(netip.MustParseAddr("10.3.3.3")); !ok {
		t.Error("v4 pod IP not cached")
	}
	if _, ok := c.cache.LookupIP(netip.MustParseAddr("fd00::1")); !ok {
		t.Error("v6 pod IP not cached")
	}
}
