package collector

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/ecojuntak/network-sniffer/internal/bpf"
	"github.com/ecojuntak/network-sniffer/internal/decode"
	"github.com/ecojuntak/network-sniffer/internal/dnscache"
)

// rawDNS builds a raw DNS ring-buffer record: a response for name with one A
// record per ip, or an NXDOMAIN response when no ips are given.
func rawDNS(t *testing.T, name string, ips ...string) []byte {
	t.Helper()
	rcode := dnsmessage.RCodeSuccess
	if len(ips) == 0 {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	n := dnsmessage.MustNewName(name)
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		h := dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 300}
		if err := b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, decode.DNSEventSize)
	binary.LittleEndian.PutUint16(raw, uint16(len(msg)))
	copy(raw[2:], msg)
	return raw
}

func TestCollectorAttachesDstHostname(t *testing.T) {
	c, m := newTestCollector(t, t.TempDir())
	c.cfg.DNS = dnscache.New(100)
	now := time.Now()

	c.handleDNS(rawDNS(t, "api.example.com.", "93.184.216.34"), now)
	c.handleDNS(rawDNS(t, "nope.example.com."), now)

	// Outbound to the resolved IP gets its name; outbound to an unresolved
	// IP and the accepted side of a call from the resolved IP do not.
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{93, 184, 216, 34}, 50000, 443, 0, true), now)
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 4, 4}, 50001, 443, 0, true), now)
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{93, 184, 216, 34}, 8080, 41000, 0, false), now)

	got := map[string]string{}
	for _, r := range c.agg.Drain() {
		dst, _ := netip.AddrFromSlice(r.GetDstIp())
		got[dst.String()+"/"+map[bool]string{true: "out", false: "in"}[r.GetOutbound()]] = r.GetDstHostname()
	}
	want := map[string]string{
		"93.184.216.34/out": "api.example.com",
		"8.8.4.4/out":       "",
		"10.0.0.1/in":       "",
	}
	for k, w := range want {
		if h, ok := got[k]; !ok || h != w {
			t.Errorf("record %s hostname = %q (present %v), want %q", k, h, ok, w)
		}
	}

	if v := testutil.ToFloat64(m.DNSAnswers.WithLabelValues(resultCached)); v != 1 {
		t.Errorf("dns cached = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.DNSAnswers.WithLabelValues(resultNotAnswer)); v != 1 {
		t.Errorf("dns not_answer = %v, want 1", v)
	}
}

func TestCollectorDNSCacheFull(t *testing.T) {
	c, m := newTestCollector(t, t.TempDir())
	c.cfg.DNS = dnscache.New(1)
	c.handleDNS(rawDNS(t, "a.example.com.", "1.1.1.1", "1.0.0.1"), time.Now())
	if v := testutil.ToFloat64(m.DNSAnswers.WithLabelValues(resultCacheFull)); v != 1 {
		t.Errorf("dns cache_full = %v, want 1", v)
	}
}

// fakeDNSSource yields its records, then reports the source closed.
type fakeDNSSource struct{ records [][]byte }

func (f *fakeDNSSource) ReadDNS() ([]byte, error) {
	if len(f.records) == 0 {
		return nil, bpf.ErrClosed
	}
	r := f.records[0]
	f.records = f.records[1:]
	return r, nil
}

func TestRunDNSFillsCache(t *testing.T) {
	c, _ := newTestCollector(t, t.TempDir())
	c.cfg.DNS = dnscache.New(100)
	src := &fakeDNSSource{records: [][]byte{rawDNS(t, "example.com.", "93.184.216.34"), []byte("short")}}
	if err := c.RunDNS(context.Background(), src); err != nil {
		t.Fatalf("RunDNS: %v", err)
	}
	if h, ok := c.cfg.DNS.Lookup(netip.MustParseAddr("93.184.216.34"), time.Now()); !ok || h != "example.com" {
		t.Errorf("Lookup = %q, %v; want example.com, true", h, ok)
	}
}

func TestDNSDisabledWithoutCache(t *testing.T) {
	c, _ := newTestCollector(t, t.TempDir())
	src := &fakeDNSSource{records: [][]byte{rawDNS(t, "example.com.", "93.184.216.34")}}
	if err := c.RunDNS(context.Background(), src); err != nil {
		t.Fatalf("RunDNS: %v", err)
	}
	if len(src.records) != 1 {
		t.Error("RunDNS read from the source with DNS disabled")
	}
	c.handle(rawEvent([4]byte{10, 0, 0, 1}, [4]byte{93, 184, 216, 34}, 50000, 443, 0, true), time.Now())
	if h := c.agg.Drain()[0].GetDstHostname(); h != "" {
		t.Errorf("hostname = %q, want empty", h)
	}
}
