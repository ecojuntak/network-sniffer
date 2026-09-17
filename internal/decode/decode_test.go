package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// buildEvent assembles a raw event buffer from field values, exercising the
// exact wire layout the decoder expects.
func buildEvent(saddr, daddr []byte, family, proto uint8, sport, dport uint16, pid uint32, comm string, outbound bool) []byte {
	b := make([]byte, EventSize)
	copy(b[offSaddr:], saddr)
	copy(b[offDaddr:], daddr)
	binary.BigEndian.PutUint16(b[offSport:], sport)
	binary.BigEndian.PutUint16(b[offDport:], dport)
	b[offFamily] = family
	b[offProtocol] = proto
	binary.LittleEndian.PutUint32(b[offPID:], pid)
	copy(b[offComm:offComm+commLen], comm)
	if outbound {
		b[offOutbound] = 1
	}
	return b
}

func TestDecodeIPv4(t *testing.T) {
	raw := buildEvent(
		[]byte{10, 0, 0, 1}, []byte{10, 0, 0, 2},
		familyIPv4, uint8(model.ProtocolTCP),
		54321, 8080, 4242, "curl", true,
	)

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if got, want := ev.SrcIP, netip.MustParseAddr("10.0.0.1"); got != want {
		t.Errorf("SrcIP = %v, want %v", got, want)
	}
	if got, want := ev.DstIP, netip.MustParseAddr("10.0.0.2"); got != want {
		t.Errorf("DstIP = %v, want %v", got, want)
	}
	if ev.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", ev.SrcPort)
	}
	if ev.DstPort != 8080 {
		t.Errorf("DstPort = %d, want 8080", ev.DstPort)
	}
	if ev.Protocol != model.ProtocolTCP {
		t.Errorf("Protocol = %v, want tcp", ev.Protocol)
	}
	if ev.PID != 4242 {
		t.Errorf("PID = %d, want 4242", ev.PID)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want curl", ev.Comm)
	}
	if !ev.Outbound {
		t.Errorf("Outbound = false, want true")
	}
}

func TestDecodeIPv6(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	raw := buildEvent(src[:], dst[:], familyIPv6, uint8(model.ProtocolUDP), 100, 53, 1, "app", false)

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if got, want := ev.SrcIP, netip.MustParseAddr("2001:db8::1"); got != want {
		t.Errorf("SrcIP = %v, want %v", got, want)
	}
	if got, want := ev.DstIP, netip.MustParseAddr("2001:db8::2"); got != want {
		t.Errorf("DstIP = %v, want %v", got, want)
	}
	if ev.DstPort != 53 || ev.Protocol != model.ProtocolUDP {
		t.Errorf("got port=%d proto=%v, want 53/udp", ev.DstPort, ev.Protocol)
	}
	if ev.Outbound {
		t.Errorf("Outbound = true, want false")
	}
}

// A v4-mapped v6 address must decode to the canonical v4 form so it matches
// cache entries keyed on the v4 address.
func TestDecodeIPv4MappedUnmapped(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:10.0.0.5").As16()
	raw := buildEvent(mapped[:], mapped[:], familyIPv6, uint8(model.ProtocolTCP), 1, 1, 0, "", false)

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if got, want := ev.SrcIP, netip.MustParseAddr("10.0.0.5"); got != want {
		t.Errorf("SrcIP = %v (is4=%v), want unmapped %v", got, got.Is4(), want)
	}
}

func TestDecodeShortBuffer(t *testing.T) {
	_, err := Decode(make([]byte, EventSize-1))
	if !errors.Is(err, ErrShortEvent) {
		t.Fatalf("err = %v, want ErrShortEvent", err)
	}
}

func TestDecodeUnknownFamily(t *testing.T) {
	raw := buildEvent([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, 99, uint8(model.ProtocolTCP), 1, 1, 0, "", false)
	_, err := Decode(raw)
	if !errors.Is(err, ErrUnknownFamily) {
		t.Fatalf("err = %v, want ErrUnknownFamily", err)
	}
}

// A larger buffer (e.g. ringbuffer slot padding) must still decode from the
// leading EventSize bytes.
func TestDecodeOversizedBuffer(t *testing.T) {
	raw := buildEvent([]byte{192, 168, 1, 1}, []byte{192, 168, 1, 2}, familyIPv4, uint8(model.ProtocolTCP), 1, 443, 0, "nginx", true)
	raw = append(raw, 0xAA, 0xBB, 0xCC)

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if ev.DstPort != 443 || ev.Comm != "nginx" {
		t.Errorf("got port=%d comm=%q, want 443/nginx", ev.DstPort, ev.Comm)
	}
}

func TestDecodeCommFullLength(t *testing.T) {
	// A comm that fills all 16 bytes with no NUL terminator.
	full := "0123456789abcdef"
	raw := buildEvent([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, familyIPv4, uint8(model.ProtocolTCP), 1, 1, 0, full, false)
	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if ev.Comm != full {
		t.Errorf("Comm = %q, want %q", ev.Comm, full)
	}
}

func TestDecodePortByteOrder(t *testing.T) {
	// Port 0x0050 == 80 must survive as 80, proving big-endian handling.
	raw := buildEvent([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, familyIPv4, uint8(model.ProtocolTCP), 0, 80, 0, "", false)
	if raw[offDport] != 0x00 || raw[offDport+1] != 0x50 {
		t.Fatalf("test setup wrong: dport bytes = %v", raw[offDport:offDport+2])
	}
	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if ev.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", ev.DstPort)
	}
}

func TestDecodeOutboundFlag(t *testing.T) {
	tests := []struct {
		name     string
		outbound bool
	}{
		{"outbound set", true},
		{"outbound unset", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := buildEvent([]byte{1, 1, 1, 1}, []byte{2, 2, 2, 2}, familyIPv4, uint8(model.ProtocolTCP), 1, 1, 0, "", tt.outbound)
			ev, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}
			if ev.Outbound != tt.outbound {
				t.Errorf("Outbound = %v, want %v", ev.Outbound, tt.outbound)
			}
		})
	}
}
