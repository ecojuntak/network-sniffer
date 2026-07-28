package resolver

import (
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func TestParseServiceEntryVIPs_StatusAddresses(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"name": "rds", "namespace": "external"},
		"spec": map[string]any{
			"hosts": []any{"mydb.eu-west-1.rds.amazonaws.com"},
		},
		"status": map[string]any{
			"addresses": []any{
				map[string]any{"value": "240.240.0.100", "host": "mydb.eu-west-1.rds.amazonaws.com"},
			},
		},
	}
	got := parseServiceEntryVIPs(obj)
	if len(got) != 1 {
		t.Fatalf("bindings = %d, want 1: %+v", len(got), got)
	}
	if got[0].ip != netip.MustParseAddr("240.240.0.100") {
		t.Fatalf("ip = %v", got[0].ip)
	}
	want := model.Workload{Name: "mydb.eu-west-1.rds.amazonaws.com", Namespace: "external", Kind: model.KindServiceEntry}
	if got[0].wl != want {
		t.Fatalf("workload = %+v, want %+v", got[0].wl, want)
	}
}

// status entry with no host falls back to the first spec host.
func TestParseServiceEntryVIPs_StatusHostFallback(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"namespace": "mesh"},
		"spec":     map[string]any{"hosts": []any{"api.example.com", "alt.example.com"}},
		"status": map[string]any{
			"addresses": []any{map[string]any{"value": "240.240.1.5"}},
		},
	}
	got := parseServiceEntryVIPs(obj)
	if len(got) != 1 || got[0].wl.Name != "api.example.com" {
		t.Fatalf("got %+v, want host api.example.com", got)
	}
}

// spec.addresses: plain IPs bind to the first host; CIDRs are skipped.
func TestParseServiceEntryVIPs_SpecAddresses(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"namespace": "external"},
		"spec": map[string]any{
			"hosts":     []any{"cache.example.com"},
			"addresses": []any{"10.9.8.7", "10.0.0.0/24"},
		},
	}
	got := parseServiceEntryVIPs(obj)
	if len(got) != 1 {
		t.Fatalf("bindings = %d, want 1 (CIDR skipped): %+v", len(got), got)
	}
	if got[0].ip != netip.MustParseAddr("10.9.8.7") {
		t.Fatalf("ip = %v, want 10.9.8.7", got[0].ip)
	}
}

// trimServiceEntry keeps only the paths parseServiceEntryVIPs reads and drops
// the heavy remainder (spec ports/selectors, status endpoints, managedFields,
// annotations, labels) the dynamic informer would otherwise retain.
func TestTrimServiceEntry_KeepsAndDropsFields(t *testing.T) {
	full := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.istio.io/v1beta1",
		"kind":       "ServiceEntry",
		"metadata": map[string]any{
			"name":          "rds",
			"namespace":     "external",
			"annotations":   map[string]any{"kubectl.kubernetes.io/last-applied-configuration": "{...big...}"},
			"labels":        map[string]any{"team": "data"},
			"managedFields": []any{map[string]any{"manager": "istiod"}},
		},
		"spec": map[string]any{
			"hosts":     []any{"mydb.eu-west-1.rds.amazonaws.com"},
			"addresses": []any{"10.9.8.7"},
			"ports": []any{
				map[string]any{"number": int64(5432), "name": "tcp-pg", "protocol": "TCP"},
			},
			"location":   "MESH_EXTERNAL",
			"resolution": "DNS",
		},
		"status": map[string]any{
			"addresses": []any{map[string]any{"value": "240.240.0.100", "host": "mydb.eu-west-1.rds.amazonaws.com"}},
		},
	}}

	out, err := trimServiceEntry(full)
	if err != nil {
		t.Fatalf("trim error: %v", err)
	}
	u, ok := out.(*unstructured.Unstructured)
	if !ok {
		t.Fatalf("trim returned %T, want *unstructured.Unstructured", out)
	}

	// Dropped top-level fields.
	if _, ok := u.Object["apiVersion"]; ok {
		t.Error("apiVersion should be dropped")
	}
	if _, ok := u.Object["kind"]; ok {
		t.Error("kind should be dropped")
	}

	md := u.Object["metadata"].(map[string]any)
	if md["name"] != "rds" || md["namespace"] != "external" {
		t.Errorf("metadata name/namespace not preserved: %+v", md)
	}
	for _, drop := range []string{"annotations", "labels", "managedFields"} {
		if _, ok := md[drop]; ok {
			t.Errorf("metadata.%s should be dropped", drop)
		}
	}

	spec := u.Object["spec"].(map[string]any)
	if _, ok := spec["hosts"]; !ok {
		t.Error("spec.hosts should be preserved")
	}
	if _, ok := spec["addresses"]; !ok {
		t.Error("spec.addresses should be preserved")
	}
	for _, drop := range []string{"ports", "location", "resolution"} {
		if _, ok := spec[drop]; ok {
			t.Errorf("spec.%s should be dropped", drop)
		}
	}

	// The trimmed object must still resolve to the same VIP binding.
	got := parseServiceEntryVIPs(u.Object)
	if len(got) != 2 {
		t.Fatalf("trimmed object bindings = %d, want 2 (status + spec address): %+v", len(got), got)
	}
}

// A non-unstructured input (tombstone wrapper, unknown type) is passed through
// unchanged so the delete path can still unwrap it.
func TestTrimServiceEntry_PassesThroughNonUnstructured(t *testing.T) {
	in := "not-unstructured"
	out, err := trimServiceEntry(in)
	if err != nil {
		t.Fatalf("trim error: %v", err)
	}
	if out != in {
		t.Fatalf("passthrough = %v, want %v", out, in)
	}
}

func TestParseServiceEntryVIPs_Empty(t *testing.T) {
	tests := []struct {
		name string
		obj  map[string]any
	}{
		{"no spec/status", map[string]any{"metadata": map[string]any{"namespace": "x"}}},
		{"host but no addresses", map[string]any{"spec": map[string]any{"hosts": []any{"h"}}}},
		{"bad ip in status", map[string]any{
			"spec":   map[string]any{"hosts": []any{"h"}},
			"status": map[string]any{"addresses": []any{map[string]any{"value": "not-an-ip"}}},
		}},
		{"addresses but no host", map[string]any{"spec": map[string]any{"addresses": []any{"10.0.0.1"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseServiceEntryVIPs(tt.obj); len(got) != 0 {
				t.Fatalf("bindings = %+v, want none", got)
			}
		})
	}
}
