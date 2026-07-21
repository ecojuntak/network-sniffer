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

func TestConnectionEventIsAWSReserved(t *testing.T) {
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
		{"src fd00:ec2::23", mk("fd00:ec2::23", "10.0.0.5"), true},
		{"dst imds", mk("10.0.0.5", "fd00:ec2::254"), true},
		{"dst vpc dns", mk("10.0.0.5", "fd00:ec2::253"), true},
		{"dst time sync", mk("10.0.0.5", "fd00:ec2::123"), true},
		{"both reserved", mk("fd00:ec2::1", "fd00:ec2::2"), true},
		{"other ula not reserved", mk("fd00:beef::1", "10.0.0.5"), false},
		{"pod v6 not reserved", mk("fd12:3456::1", "10.0.0.5"), false},
		{"v4 not reserved", mk("10.0.0.5", "10.0.0.6"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.IsAWSReserved(); got != tt.want {
				t.Fatalf("IsAWSReserved() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnectionEventHasEphemeralDestPort(t *testing.T) {
	tests := []struct {
		name string
		port uint16
		want bool
	}{
		{"http service", 80, false},
		{"https service", 443, false},
		{"postgres", 5432, false},
		{"high service port", 8080, false},
		{"nodeport top", 32767, false},
		{"ephemeral min", 32768, true},
		{"ephemeral mid", 45000, true},
		{"ephemeral max", 60999, true},
		{"zero port", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := ConnectionEvent{DstPort: tt.port}
			if got := ev.HasEphemeralDestPort(); got != tt.want {
				t.Fatalf("HasEphemeralDestPort() DstPort=%d = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}
