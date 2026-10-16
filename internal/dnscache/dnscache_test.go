package dnscache

import (
	"net/netip"
	"testing"
	"time"
)

var (
	t0  = time.Unix(1_700_000_000, 0)
	ip1 = netip.MustParseAddr("93.184.216.34")
	ip2 = netip.MustParseAddr("2606:2800:220:1::1")
	ip3 = netip.MustParseAddr("1.1.1.1")
)

func TestLookup(t *testing.T) {
	c := New(10)
	if _, ok := c.Lookup(ip1, t0); ok {
		t.Fatal("empty cache: want miss")
	}
	c.Put(ip1, "example.com", 5*time.Minute, t0)
	if got, ok := c.Lookup(ip1, t0.Add(4*time.Minute)); !ok || got != "example.com" {
		t.Errorf("Lookup = %q, %v; want example.com, true", got, ok)
	}
	if _, ok := c.Lookup(ip1, t0.Add(5*time.Minute)); ok {
		t.Error("expired entry: want miss")
	}
}

func TestLookupUnmapsV4InV6(t *testing.T) {
	c := New(10)
	c.Put(netip.MustParseAddr("::ffff:93.184.216.34"), "example.com", time.Minute, t0)
	if got, ok := c.Lookup(ip1, t0); !ok || got != "example.com" {
		t.Errorf("Lookup = %q, %v; want example.com, true", got, ok)
	}
}

func TestTTLClamp(t *testing.T) {
	c := New(10)
	c.Put(ip1, "short.example.com", time.Second, t0)
	c.Put(ip2, "long.example.com", 24*time.Hour, t0)

	if _, ok := c.Lookup(ip1, t0.Add(MinTTL-time.Second)); !ok {
		t.Error("short TTL: want hit before MinTTL")
	}
	if _, ok := c.Lookup(ip1, t0.Add(MinTTL)); ok {
		t.Error("short TTL: want miss at MinTTL")
	}
	if _, ok := c.Lookup(ip2, t0.Add(MaxTTL-time.Second)); !ok {
		t.Error("long TTL: want hit before MaxTTL")
	}
	if _, ok := c.Lookup(ip2, t0.Add(MaxTTL)); ok {
		t.Error("long TTL: want miss at MaxTTL")
	}
}

func TestLastWriteWins(t *testing.T) {
	c := New(10)
	c.Put(ip1, "a.example.com", time.Minute, t0)
	c.Put(ip1, "b.example.com", time.Minute, t0.Add(time.Second))
	if got, _ := c.Lookup(ip1, t0.Add(time.Second)); got != "b.example.com" {
		t.Errorf("Lookup = %q, want b.example.com", got)
	}
}

func TestCapacity(t *testing.T) {
	c := New(2)
	if !c.Put(ip1, "one", time.Minute, t0) || !c.Put(ip2, "two", 10*time.Minute, t0) {
		t.Fatal("Put under capacity: want true")
	}
	if c.Put(ip3, "three", time.Minute, t0) {
		t.Error("Put into full cache: want false")
	}
	if !c.Put(ip1, "one-again", time.Minute, t0) {
		t.Error("update of held IP in full cache: want true")
	}
	// ip1 expires at t0+1m; inserting after that sweeps it to make room.
	if !c.Put(ip3, "three", time.Minute, t0.Add(2*time.Minute)) {
		t.Error("Put after expiry: want true")
	}
	if _, ok := c.Lookup(ip3, t0.Add(2*time.Minute)); !ok {
		t.Error("ip3: want hit")
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2", c.Len())
	}
}

func TestSweep(t *testing.T) {
	c := New(10)
	c.Put(ip1, "one", time.Minute, t0)
	c.Put(ip2, "two", 10*time.Minute, t0)
	if n := c.Sweep(t0.Add(5 * time.Minute)); n != 1 {
		t.Errorf("Sweep = %d, want 1", n)
	}
	if _, ok := c.Lookup(ip2, t0.Add(5*time.Minute)); !ok {
		t.Error("unexpired entry swept")
	}
}
