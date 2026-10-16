package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// DNS record wire format (packed). The C side (bpf/sniffer.c, struct
// dns_event) writes exactly this layout:
//
//	offset  size  field
//	0       2     len     (little-endian host order; valid payload bytes)
//	2       512   payload (raw DNS message, UDP payload)
//	--------------------------------------------------
//	514           total
const (
	// DNSEventSize is the fixed size in bytes of one raw DNS record.
	DNSEventSize  = dnsOffPayload + dnsMaxPayload
	dnsOffPayload = 2
	dnsMaxPayload = 512
)

// ErrNotDNSAnswer is returned for a message that is not a successful DNS
// response with exactly one question.
var ErrNotDNSAnswer = errors.New("decode: not a successful single-question DNS response")

// ErrBadDNSLength is returned when the record's length field is out of range.
var ErrBadDNSLength = errors.New("decode: DNS payload length out of range")

// DecodeDNS parses one raw DNS record into its address answers. Every A and
// AAAA record is attributed to the question name — the name the application
// asked for — so a CNAME chain collapses onto it. Names are lowercased without
// the trailing dot. Payloads cut at the 512-byte capture limit are parsed
// best-effort: answers decoded before the cut are returned without error.
func DecodeDNS(b []byte) ([]model.DNSAnswer, error) {
	if len(b) < DNSEventSize {
		return nil, ErrShortEvent
	}
	n := int(binary.LittleEndian.Uint16(b[:dnsOffPayload]))
	if n == 0 || n > dnsMaxPayload {
		return nil, ErrBadDNSLength
	}
	msg := b[dnsOffPayload : dnsOffPayload+n]

	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil, ErrNotDNSAnswer
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	if len(qs) != 1 {
		return nil, ErrNotDNSAnswer
	}
	name := normalizeName(qs[0].Name)
	if name == "" {
		return nil, ErrNotDNSAnswer
	}

	var out []model.DNSAnswer
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			// ErrSectionDone ends a complete message; anything else is a
			// truncated or malformed tail — keep what parsed so far.
			return out, nil
		}
		var ip netip.Addr
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, nil
			}
			ip = netip.AddrFrom4(r.A)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, nil
			}
			ip = netip.AddrFrom16(r.AAAA).Unmap()
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, nil
			}
			continue
		}
		out = append(out, model.DNSAnswer{Name: name, IP: ip, TTL: rh.TTL})
	}
}

// normalizeName lowercases a DNS name and strips the trailing root dot.
func normalizeName(n dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(n.String(), "."))
}
