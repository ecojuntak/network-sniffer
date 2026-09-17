package model

import (
	"net/netip"
	"testing"
)

func TestNormalizeL7(t *testing.T) {
	tests := []struct {
		name        string
		appProtocol string
		portName    string
		want        string
	}{
		{"appProtocol wins over name", "grpc", "http-web", "grpc"},
		{"appProtocol grpc-web kept whole", "grpc-web", "", "grpc-web"},
		{"name prefix http", "", "http-web", "http"},
		{"name prefix grpc", "", "grpc", "grpc"},
		{"name prefix http2", "", "http2-foo", "http2"},
		{"bare tcp name", "", "tcp", "tcp"},
		{"unrecognized name -> empty", "", "metrics", ""},
		{"unrecognized prefix -> empty", "", "admin-web", ""},
		{"empty inputs -> empty", "", "", ""},
		{"uppercase normalized", "GRPC", "", "grpc"},
		{"whitespace trimmed", "  http  ", "", "http"},
		{"unrecognized appProtocol falls through to empty", "thrift", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeL7(tt.appProtocol, tt.portName); got != tt.want {
				t.Errorf("NormalizeL7(%q, %q) = %q, want %q", tt.appProtocol, tt.portName, got, tt.want)
			}
		})
	}
}

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

func TestConnectionEventIsLinkLocal(t *testing.T) {
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
		{"dst imds", mk("10.0.0.5", "169.254.169.254"), true},
		{"src link-local v4", mk("169.254.1.2", "10.0.0.5"), true},
		{"dst link-local v6", mk("10.0.0.5", "fe80::1"), true},
		{"cgnat not link-local", mk("100.90.100.163", "10.0.0.5"), false},
		{"normal v4", mk("10.0.0.5", "10.0.0.6"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.IsLinkLocal(); got != tt.want {
				t.Fatalf("IsLinkLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnectionEventCanonical(t *testing.T) {
	outbound := ConnectionEvent{
		SrcIP: netip.MustParseAddr("10.0.0.1"), SrcPort: 54321,
		DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 8080,
		PID: 42, Comm: "curl", Outbound: true,
	}
	if got := outbound.Canonical(); got != outbound {
		t.Fatalf("Canonical() on outbound event changed it: got %+v, want unchanged %+v", got, outbound)
	}

	inbound := ConnectionEvent{
		SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 8080,
		DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 54321,
		Outbound: false,
	}
	got := inbound.Canonical()
	want := ConnectionEvent{
		SrcIP: netip.MustParseAddr("10.0.0.1"), SrcPort: 54321,
		DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 8080,
		Outbound: false,
	}
	if got != want {
		t.Fatalf("Canonical() on inbound event = %+v, want %+v", got, want)
	}
}

func TestConnectionEventIsReversedDuplicate(t *testing.T) {
	tests := []struct {
		name     string
		outbound bool
		source   Workload
		want     bool
	}{
		{"inbound record, in-cluster source -> reversed duplicate", false, Workload{Kind: "Deployment"}, true},
		{"inbound record, node source -> reversed duplicate", false, Workload{Kind: KindNode}, true},
		{"inbound record, external source -> kept", false, Workload{Kind: KindExternal}, false},
		{"outbound record, in-cluster source -> kept", true, Workload{Kind: "Deployment"}, false},
		{"outbound record, external source -> kept", true, Workload{Kind: KindExternal}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := ConnectionEvent{Outbound: tt.outbound}
			if got := ev.IsReversedDuplicate(tt.source); got != tt.want {
				t.Fatalf("IsReversedDuplicate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConnectionEventIsSelfEdge(t *testing.T) {
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
		{"cgnat self v4", mk("100.90.106.4", "100.90.106.4"), true},
		{"normal self v4", mk("10.0.0.5", "10.0.0.5"), true},
		{"self v6", mk("2001:db8::1", "2001:db8::1"), true},
		{"distinct v4", mk("100.90.106.4", "100.90.106.5"), false},
		{"distinct v6", mk("2001:db8::1", "2001:db8::2"), false},
		{"v4 mapped equals v6", mk("::ffff:10.0.0.5", "10.0.0.5"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.IsSelfEdge(); got != tt.want {
				t.Fatalf("IsSelfEdge() = %v, want %v", got, tt.want)
			}
		})
	}
}
