// Package dedup collapses repeated identical service calls within a time
// window so a busy node does not flood the log with the same edge. It is a
// pure, clock-injected component: callers pass the current time, keeping it
// deterministic and testable.
package dedup

import (
	"fmt"
	"sync"
	"time"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Deduper allows the first sighting of a service-call edge and then suppresses
// identical edges until the window elapses. The zero value is not usable;
// construct with New.
type Deduper struct {
	window time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

// New returns a Deduper that suppresses duplicate edges for the given window.
// A non-positive window disables suppression (every call is allowed).
func New(window time.Duration) *Deduper {
	return &Deduper{
		window: window,
		seen:   make(map[string]time.Time),
	}
}

// Allow reports whether sc should be logged given the current time now. It
// returns true for a first sighting or once the window since the last allowed
// sighting has elapsed, and records now as the new sighting time in that case.
func (d *Deduper) Allow(sc model.ServiceCall, now time.Time) bool {
	if d.window <= 0 {
		return true
	}
	k := key(sc)

	d.mu.Lock()
	defer d.mu.Unlock()

	last, ok := d.seen[k]
	if ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[k] = now
	return true
}

// Sweep evicts entries whose window has fully elapsed as of now, bounding
// memory on long-running processes. It returns the number of entries evicted.
func (d *Deduper) Sweep(now time.Time) int {
	if d.window <= 0 {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	n := 0
	for k, last := range d.seen {
		if now.Sub(last) >= d.window {
			delete(d.seen, k)
			n++
		}
	}
	return n
}

// key builds the dedup identity of an edge: the fields that make it distinct
// in the dependency map.
func key(sc model.ServiceCall) string {
	return fmt.Sprintf("%s/%s|%s/%s|%d|%d",
		sc.Source.Namespace, sc.Source.Name,
		sc.Dest.Namespace, sc.Dest.Name,
		sc.DestPort, sc.DestProtocol,
	)
}
