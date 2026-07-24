package ignore

import (
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func TestCompileRejects(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{"catch-all rejected", "*/*"},
		{"missing slash", "kube-system"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile([]string{tt.pattern}); err == nil {
				t.Fatalf("Compile(%q) = nil error, want error", tt.pattern)
			}
		})
	}
}

func TestMatcherShouldIgnore(t *testing.T) {
	m, err := Compile([]string{
		"kube-system/*",
		"*/istiod",
		"*/vmagent-*",
		"/ip-*",  // empty namespace (node identity)
		"*/10.*", // external IP peer
		"istio-system/*",
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := []struct {
		name      string
		namespace string
		workload  string
		want      bool
	}{
		{"whole-segment glob", "kube-system", "coredns", true},
		{"exact name any ns", "mesh", "istiod", true},
		{"prefix glob", "obs", "vmagent-0", true},
		{"prefix glob requires dash", "obs", "vmagent", false},
		{"node empty ns ip prefix", "", "ip-100-90-88-185.eu-west-1.compute.internal", true},
		{"node ip but non-empty ns not matched by /ip-*", "shop", "ip-x", false},
		{"external ip 10.x", "", "10.0.0.5", true},
		{"istio-system whole", "istio-system", "istio-ingressgateway", true},
		{"unrelated pod kept", "shop", "checkout", false},
		{"empty ns non-ip kept", "", "34.117.59.81", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.ShouldIgnore(tt.namespace, tt.workload); got != tt.want {
				t.Fatalf("ShouldIgnore(%q,%q) = %v, want %v", tt.namespace, tt.workload, got, tt.want)
			}
		})
	}
}

// "vmagent" without the trailing char: prefix glob vmagent-* requires the dash,
// so bare "vmagent" must NOT match. Guards against translating * too loosely.
func TestPrefixGlobBoundary(t *testing.T) {
	m, _ := Compile([]string{"*/vmagent-*"})
	if m.ShouldIgnore("obs", "vmagent") {
		t.Fatal("vmagent-* must not match bare 'vmagent'")
	}
	if !m.ShouldIgnore("obs", "vmagent-agent-0") {
		t.Fatal("vmagent-* must match 'vmagent-agent-0'")
	}
}

func TestShouldIgnoreCall(t *testing.T) {
	m, _ := Compile([]string{"/ip-*", "istio-system/*"})
	// Node-sourced probe edge: source is the node identity (empty ns, ip-*).
	probe := model.ServiceCall{
		Source: model.Workload{Name: "ip-100-90-88-185.eu-west-1.compute.internal"},
		Dest:   model.Workload{Name: "challenge-service-consumer", Namespace: "challenge-service"},
	}
	if !m.ShouldIgnoreCall(probe) {
		t.Fatal("probe edge should be ignored via source /ip-*")
	}
	// Dest in istio-system: ignored via dest.
	toMesh := model.ServiceCall{
		Source: model.Workload{Name: "checkout", Namespace: "shop"},
		Dest:   model.Workload{Name: "istiod", Namespace: "istio-system"},
	}
	if !m.ShouldIgnoreCall(toMesh) {
		t.Fatal("edge to istio-system should be ignored via dest")
	}
	// Neither endpoint matches: kept.
	keep := model.ServiceCall{
		Source: model.Workload{Name: "frontend", Namespace: "shop"},
		Dest:   model.Workload{Name: "checkout", Namespace: "shop"},
	}
	if m.ShouldIgnoreCall(keep) {
		t.Fatal("shop->shop edge must be kept")
	}
}

// A nil / empty Matcher ignores nothing.
func TestEmptyMatcher(t *testing.T) {
	m, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	if m.ShouldIgnore("kube-system", "coredns") {
		t.Fatal("empty matcher must ignore nothing")
	}
}
