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
