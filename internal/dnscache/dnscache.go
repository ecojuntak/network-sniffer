// Package dnscache holds the node-local IP -> hostname mapping learned from
// DNS answers observed by the eBPF probe. The collector consults it to name
// the destination of outbound connections; the processor only uses that name
// when the destination has no cluster identity.
package dnscache

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// MinTTL is the shortest lifetime of an entry. Applications commonly
	// keep using an address past its DNS TTL (resolver caches, connection
	// pools, Java's 30s default), and many CDNs answer with TTLs of a few
	// seconds, so the raw TTL would expire names before they are used.
	MinTTL = time.Minute
	// MaxTTL is the longest lifetime of an entry, bounding how long a name
	// can stick to an IP that has since been reassigned.
	MaxTTL = 30 * time.Minute
)

type entry struct {
	name    string
	expires time.Time
}

// Cache maps IPs to the hostname they were most recently resolved from. The
// last answer wins when several names resolve to one IP (shared CDN or load
// balancer addresses). It is bounded and safe for concurrent use.
type Cache struct {
	max int

	mu      sync.Mutex
	entries map[netip.Addr]entry
}

// New returns an empty Cache holding at most maxEntries IPs.
func New(maxEntries int) *Cache {
	return &Cache{max: maxEntries, entries: make(map[netip.Addr]entry)}
}

// Put records that ip was resolved from name with the given DNS TTL, clamped
// to [MinTTL, MaxTTL]. When the cache is full it first sweeps expired entries;
// if it is still full a new IP is not stored and Put reports false. Updating
// an IP already held always succeeds.
func (c *Cache) Put(ip netip.Addr, name string, ttl time.Duration, now time.Time) bool {
	ttl = min(max(ttl, MinTTL), MaxTTL)
	ip = ip.Unmap()

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[ip]; !ok && len(c.entries) >= c.max {
		c.sweepLocked(now)
		if len(c.entries) >= c.max {
			return false
		}
	}
	c.entries[ip] = entry{name: name, expires: now.Add(ttl)}
	return true
}

// Lookup returns the hostname ip was resolved from, if an unexpired answer
// for it was seen.
func (c *Cache) Lookup(ip netip.Addr, now time.Time) (string, bool) {
	c.mu.Lock()
	e, ok := c.entries[ip.Unmap()]
	c.mu.Unlock()
	if !ok || !now.Before(e.expires) {
		return "", false
	}
	return e.name, true
}

// Sweep removes expired entries and returns the number of entries left.
func (c *Cache) Sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	return len(c.entries)
}

func (c *Cache) sweepLocked(now time.Time) {
	for ip, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, ip)
		}
	}
}

// Len returns the number of entries held, including expired ones not yet
// swept.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
