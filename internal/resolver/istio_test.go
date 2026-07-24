package resolver

import (
	"net/netip"
	"testing"

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
