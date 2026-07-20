// Package decode turns the raw byte record emitted by the eBPF program over
// the ring buffer into a typed model.ConnectionEvent.
//
// Wire format (packed, little-endian host fields, network-order addresses and
// ports). The C side (bpf/sniffer.c) writes exactly this layout:
//
//	offset  size  field
//	0       16    saddr   (network-order bytes; v4 uses first 4)
//	16      16    daddr   (network-order bytes; v4 uses first 4)
//	32      2     sport   (big-endian / network order)
//	34      2     dport   (big-endian / network order)
//	36      1     family  (AF_INET=2, AF_INET6=10)
//	37      1     protocol(IP protocol number)
//	38      4     pid     (little-endian host order)
//	42      16    comm    (NUL-padded process name)
//	--------------------------------------------------
//	58            total
//
// Offsets are read explicitly rather than via a struct so the decoder is
// immune to Go/C struct-padding differences and is trivially testable.
package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// EventSize is the fixed size in bytes of one raw event record.
const EventSize = 58

// Address family values as used by the kernel.
const (
	familyIPv4 = 2  // AF_INET
	familyIPv6 = 10 // AF_INET6
)

const (
	offSaddr    = 0
	offDaddr    = 16
	offSport    = 32
	offDport    = 34
	offFamily   = 36
	offProtocol = 37
	offPID      = 38
	offComm     = 42
	commLen     = 16
)

// ErrShortEvent is returned when the buffer is smaller than EventSize.
var ErrShortEvent = errors.New("decode: buffer smaller than event size")

// ErrUnknownFamily is returned for an address family that is neither IPv4 nor
// IPv6.
var ErrUnknownFamily = errors.New("decode: unknown address family")

// Decode parses one raw event record. The returned ConnectionEvent addresses
// are unmapped canonical netip.Addr values.
func Decode(b []byte) (model.ConnectionEvent, error) {
	if len(b) < EventSize {
		return model.ConnectionEvent{}, ErrShortEvent
	}

	family := b[offFamily]
	src, err := decodeAddr(b[offSaddr:offSaddr+16], family)
	if err != nil {
		return model.ConnectionEvent{}, err
	}
	dst, err := decodeAddr(b[offDaddr:offDaddr+16], family)
	if err != nil {
		return model.ConnectionEvent{}, err
	}

	return model.ConnectionEvent{
		SrcIP:    src,
		DstIP:    dst,
		SrcPort:  binary.BigEndian.Uint16(b[offSport : offSport+2]),
		DstPort:  binary.BigEndian.Uint16(b[offDport : offDport+2]),
		Protocol: model.Protocol(b[offProtocol]),
		PID:      binary.LittleEndian.Uint32(b[offPID : offPID+4]),
		Comm:     decodeComm(b[offComm : offComm+commLen]),
	}, nil
}

// decodeAddr converts the 16 network-order address bytes into a netip.Addr,
// using only the first 4 bytes for IPv4.
func decodeAddr(raw []byte, family uint8) (netip.Addr, error) {
	switch family {
	case familyIPv4:
		var a [4]byte
		copy(a[:], raw[:4])
		return netip.AddrFrom4(a), nil
	case familyIPv6:
		var a [16]byte
		copy(a[:], raw[:16])
		// Unmap so a v4-in-v6 address compares equal to its v4 form.
		return netip.AddrFrom16(a).Unmap(), nil
	default:
		return netip.Addr{}, ErrUnknownFamily
	}
}

// decodeComm reads a NUL-padded fixed-length process name.
func decodeComm(raw []byte) string {
	for i, c := range raw {
		if c == 0 {
			return string(raw[:i])
		}
	}
	return string(raw)
}
