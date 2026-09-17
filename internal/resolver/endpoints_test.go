package resolver

import (
	"net/netip"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func findEntry(entries []portEntry, ip string, port uint16) (portEntry, bool) {
	want := netip.MustParseAddr(ip)
	for _, e := range entries {
		if e.ip == want && e.port == port {
			return e, true
		}
	}
	return portEntry{}, false
}

func TestServiceEntries(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "172.20.0.10",
			ClusterIPs: []string{"172.20.0.10"},
			Ports: []corev1.ServicePort{
				{Name: "grpc", Port: 8080},                                 // name convention
				{Name: "http-web", Port: 80},                               // name prefix
				{Name: "custom", Port: 9000, AppProtocol: ptr.To("http2")}, // appProtocol wins
				{Name: "metrics", Port: 9090},                              // unrecognized -> skipped
			},
		},
	}

	entries := serviceEntries(svc)

	if e, ok := findEntry(entries, "172.20.0.10", 8080); !ok || e.l7 != "grpc" {
		t.Errorf("grpc port = %+v, ok=%v", e, ok)
	}
	if e, ok := findEntry(entries, "172.20.0.10", 80); !ok || e.l7 != "http" {
		t.Errorf("http port = %+v, ok=%v", e, ok)
	}
	if e, ok := findEntry(entries, "172.20.0.10", 9000); !ok || e.l7 != "http2" {
		t.Errorf("http2 port = %+v, ok=%v", e, ok)
	}
	if _, ok := findEntry(entries, "172.20.0.10", 9090); ok {
		t.Error("metrics port should be skipped (unrecognized protocol)")
	}
}

// Headless Services (ClusterIP None) expose no ClusterIP endpoints.
func TestServiceEntriesHeadless(t *testing.T) {
	svc := &corev1.Service{
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Ports:     []corev1.ServicePort{{Name: "grpc", Port: 8080}},
		},
	}
	if entries := serviceEntries(svc); len(entries) != 0 {
		t.Errorf("headless service yielded %d entries, want 0", len(entries))
	}
}

func TestEndpointSliceEntries(t *testing.T) {
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-abc", Namespace: "shop"},
		Ports: []discoveryv1.EndpointPort{
			{Name: ptr.To("grpc"), Port: ptr.To[int32](8080)},
			{Name: ptr.To("metrics"), Port: ptr.To[int32](9090)}, // unrecognized -> skipped
			{Name: ptr.To("http"), Port: nil},                    // nil port -> skipped
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.1.5", "10.0.1.6"}},
			{Addresses: []string{"10.0.1.7"}},
		},
	}

	entries := endpointSliceEntries(es)

	for _, ip := range []string{"10.0.1.5", "10.0.1.6", "10.0.1.7"} {
		if e, ok := findEntry(entries, ip, 8080); !ok || e.l7 != "grpc" {
			t.Errorf("grpc endpoint %s = %+v, ok=%v", ip, e, ok)
		}
		if _, ok := findEntry(entries, ip, 9090); ok {
			t.Errorf("metrics endpoint %s should be skipped", ip)
		}
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3 (one recognized port x three addresses)", len(entries))
	}
}

func TestParseEntriesNilSafe(t *testing.T) {
	if serviceEntries(nil) != nil {
		t.Error("serviceEntries(nil) should be nil")
	}
	if endpointSliceEntries(nil) != nil {
		t.Error("endpointSliceEntries(nil) should be nil")
	}
}

func TestEndpointSliceClusterIPEntries(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "172.20.0.10",
			ClusterIPs: []string{"172.20.0.10"},
			Ports:      []corev1.ServicePort{{Name: "grpc", Port: 8080}},
		},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout-abc", Namespace: "shop",
			Labels: map[string]string{"kubernetes.io/service-name": "checkout"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5", "10.0.1.6"}}},
	}

	entries := endpointSliceClusterIPEntries(es, svc)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].clusterIP.String() != "172.20.0.10" {
		t.Errorf("got clusterIP %s, want 172.20.0.10", entries[0].clusterIP)
	}
	if entries[0].podIP.String() != "10.0.1.5" {
		t.Errorf("got podIP %s, want 10.0.1.5 (first valid pod IP)", entries[0].podIP)
	}
}

// A headless Service (no ClusterIP) produces no ClusterIP entries; its pods
// are still covered via the port-index path (endpointSliceEntries).
func TestEndpointSliceClusterIPEntriesHeadless(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "headless-abc", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "headless"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.5"}}},
	}
	if entries := endpointSliceClusterIPEntries(es, svc); entries != nil {
		t.Errorf("headless service should produce no ClusterIP entries, got %d", len(entries))
	}
}

// No backing pod IPs (e.g. an EndpointSlice with an empty address list) means
// there is nothing to redirect the ClusterIP to.
func TestEndpointSliceClusterIPEntriesNoPods(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: "172.20.0.20", ClusterIPs: []string{"172.20.0.20"}},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "empty-abc", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "empty"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{}}},
	}
	if entries := endpointSliceClusterIPEntries(es, svc); entries != nil {
		t.Errorf("service with no pod IPs should produce no entries, got %d", len(entries))
	}
}

// A dual-stack Service produces one entry per ClusterIP, all pointing at the
// same backing pod IP.
func TestEndpointSliceClusterIPEntriesMultipleClusterIPs(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "dual-stack", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "172.20.0.30",
			ClusterIPs: []string{"172.20.0.30", "fd00::1234"},
		},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dual-stack-abc", Namespace: "default",
			Labels: map[string]string{"kubernetes.io/service-name": "dual-stack"},
		},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.1.10"}}},
	}

	entries := endpointSliceClusterIPEntries(es, svc)
	if len(entries) != 2 {
		t.Fatalf("dual-stack service should produce 2 entries, got %d", len(entries))
	}
	seen := make(map[string]bool)
	for _, e := range entries {
		seen[e.clusterIP.String()] = true
		if e.podIP.String() != "10.0.1.10" {
			t.Errorf("got podIP %s, want 10.0.1.10", e.podIP)
		}
	}
	if !seen["172.20.0.30"] || !seen["fd00::1234"] {
		t.Errorf("missing a ClusterIP entry, got %v", seen)
	}
}

func TestEndpointSliceClusterIPEntriesNilSafe(t *testing.T) {
	svc := &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: "172.20.0.1"}}
	es := &discoveryv1.EndpointSlice{}
	if endpointSliceClusterIPEntries(nil, svc) != nil {
		t.Error("nil EndpointSlice should return nil")
	}
	if endpointSliceClusterIPEntries(es, nil) != nil {
		t.Error("nil Service should return nil")
	}
}
