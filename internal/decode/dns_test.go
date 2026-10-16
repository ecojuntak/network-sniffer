package decode

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// rr is one answer record for buildDNS: a CNAME when cname is set, otherwise
// an A or AAAA record for ip.
type rr struct {
	name  string
	ip    string
	cname string
	ttl   uint32
}

// buildDNS builds a DNS message for question q with the given answers.
func buildDNS(t *testing.T, response bool, rcode dnsmessage.RCode, q string, answers ...rr) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: response, RCode: rcode})
	b.EnableCompression()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	for _, a := range answers {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(a.name), Class: dnsmessage.ClassINET, TTL: a.ttl}
		switch {
		case a.cname != "":
			must(b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(a.cname)}))
		case netip.MustParseAddr(a.ip).Is4():
			must(b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(a.ip).As4()}))
		default:
			must(b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(a.ip).As16()}))
		}
	}
	msg, err := b.Finish()
	must(err)
	return msg
}

// dnsRecord wraps a DNS message into the raw ring-buffer record layout,
// cutting it at the capture limit like the eBPF program does.
func dnsRecord(msg []byte) []byte {
	b := make([]byte, DNSEventSize)
	n := min(len(msg), dnsMaxPayload)
	binary.LittleEndian.PutUint16(b, uint16(n))
	copy(b[dnsOffPayload:], msg[:n])
	return b
}

func TestDecodeDNSAnswers(t *testing.T) {
	tests := []struct {
		name    string
		q       string
		answers []rr
		want    []model.DNSAnswer
	}{
		{
			name:    "A",
			q:       "API.Example.com.",
			answers: []rr{{name: "api.example.com.", ip: "93.184.216.34", ttl: 300}},
			want:    []model.DNSAnswer{{Name: "api.example.com", IP: netip.MustParseAddr("93.184.216.34"), TTL: 300}},
		},
		{
			name:    "AAAA",
			q:       "example.com.",
			answers: []rr{{name: "example.com.", ip: "2606:2800:220:1::1", ttl: 60}},
			want:    []model.DNSAnswer{{Name: "example.com", IP: netip.MustParseAddr("2606:2800:220:1::1"), TTL: 60}},
		},
		{
			name: "CNAME chain maps to question name",
			q:    "db.example.com.",
			answers: []rr{
				{name: "db.example.com.", cname: "db.eu-west-1.rds.amazonaws.com.", ttl: 5},
				{name: "db.eu-west-1.rds.amazonaws.com.", ip: "10.20.0.5", ttl: 5},
				{name: "db.eu-west-1.rds.amazonaws.com.", ip: "10.20.0.6", ttl: 5},
			},
			want: []model.DNSAnswer{
				{Name: "db.example.com", IP: netip.MustParseAddr("10.20.0.5"), TTL: 5},
				{Name: "db.example.com", IP: netip.MustParseAddr("10.20.0.6"), TTL: 5},
			},
		},
		{
			name: "no address records",
			q:    "example.com.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeDNS(dnsRecord(buildDNS(t, true, dnsmessage.RCodeSuccess, tt.q, tt.answers...)))
			if err != nil {
				t.Fatalf("DecodeDNS: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d answers %v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("answer %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDecodeDNSRejects(t *testing.T) {
	a := rr{name: "example.com.", ip: "1.2.3.4", ttl: 30}
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{"query", dnsRecord(buildDNS(t, false, dnsmessage.RCodeSuccess, "example.com.")), ErrNotDNSAnswer},
		{"nxdomain", dnsRecord(buildDNS(t, true, dnsmessage.RCodeNameError, "nope.example.com.")), ErrNotDNSAnswer},
		{"short buffer", make([]byte, 10), ErrShortEvent},
		{"zero length", dnsRecord(nil), ErrBadDNSLength},
		{"length over limit", func() []byte {
			b := dnsRecord(buildDNS(t, true, dnsmessage.RCodeSuccess, "example.com.", a))
			binary.LittleEndian.PutUint16(b, dnsMaxPayload+1)
			return b
		}(), ErrBadDNSLength},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeDNS(tt.raw); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := DecodeDNS(dnsRecord([]byte("not a dns message at all"))); err == nil {
		t.Error("garbage: want error")
	}
}

func TestDecodeDNSTruncated(t *testing.T) {
	answers := make([]rr, 40)
	for i := range answers {
		answers[i] = rr{name: "big.example.com.", ip: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}).String(), ttl: 30}
	}
	msg := buildDNS(t, true, dnsmessage.RCodeSuccess, "big.example.com.", answers...)
	if len(msg) <= dnsMaxPayload {
		t.Fatalf("test message is %d bytes, want > %d", len(msg), dnsMaxPayload)
	}

	got, err := DecodeDNS(dnsRecord(msg))
	if err != nil {
		t.Fatalf("DecodeDNS: %v", err)
	}
	if len(got) == 0 || len(got) >= len(answers) {
		t.Fatalf("got %d answers, want a non-empty prefix of %d", len(got), len(answers))
	}
	for i, a := range got {
		if a.Name != "big.example.com" || a.IP != netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}) {
			t.Errorf("answer %d = %+v", i, a)
		}
	}
}
