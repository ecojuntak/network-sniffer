package model

import "testing"

func TestProtocolString(t *testing.T) {
	tests := []struct {
		name string
		p    Protocol
		want string
	}{
		{"tcp", ProtocolTCP, "tcp"},
		{"udp", ProtocolUDP, "udp"},
		{"sctp", ProtocolSCTP, "sctp"},
		{"unknown", Protocol(200), "proto-200"},
		{"zero", Protocol(0), "proto-0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Fatalf("Protocol(%d).String() = %q, want %q", tt.p, got, tt.want)
			}
		})
	}
}

func TestWorkloadIsExternal(t *testing.T) {
	if !(Workload{Name: "1.2.3.4", Kind: KindExternal}).IsExternal() {
		t.Fatal("external workload reported non-external")
	}
	if (Workload{Name: "api", Namespace: "shop", Kind: "Deployment"}).IsExternal() {
		t.Fatal("Deployment workload reported external")
	}
	if (Workload{}).IsExternal() {
		t.Fatal("zero workload should not be external (empty kind != external)")
	}
}
