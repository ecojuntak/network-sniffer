package model

import (
	"net/netip"
	"testing"
)

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

func TestConnectionEventIsLoopback(t *testing.T) {
	mk := func(src, dst string) ConnectionEvent {
		return ConnectionEvent{
			SrcIP: netip.MustParseAddr(src),
			DstIP: netip.MustParseAddr(dst),
		}
	}
	tests := []struct {
		name string
		ev   ConnectionEvent
		want bool
	}{
		{"src loopback v4", mk("127.0.0.1", "10.0.0.5"), true},
		{"dst loopback v4", mk("10.0.0.5", "127.0.0.1"), true},
		{"both loopback v4", mk("127.0.0.1", "127.0.0.1"), true},
		{"loopback high v4", mk("127.5.6.7", "10.0.0.5"), true},
		{"loopback v6", mk("10.0.0.5", "::1"), true},
		{"no loopback", mk("10.0.0.5", "10.0.0.6"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.IsLoopback(); got != tt.want {
				t.Fatalf("IsLoopback() = %v, want %v", got, tt.want)
			}
		})
	}
}
