// Package resolver maps IP addresses to the kubernetes workload that owns
// them. The pure pieces here — the concurrent IP->Workload cache and the
// owner-chain walk that turns a pod into its top-level workload — carry no
// external dependencies and are fully unit-tested. The client-go informer
// wiring that feeds the cache lives in a linux-tagged file.
package resolver

import (
	"net/netip"
	"sync"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Store looks up the workload that owns an IP address.
type Store interface {
	// LookupIP returns the workload for ip and true, or a zero Workload and
	// false when the IP is unknown to the cache.
	LookupIP(ip netip.Addr) (model.Workload, bool)
}

// Cache is a concurrency-safe store fed by the k8s watch layer. It keys
// workloads by both pod/node IP (byIP) and pod UID (byUID); the UID index backs
// PID-based source resolution, where a local process's cgroup yields the pod
// UID but not an IP. The zero value is not usable; construct with NewCache.
type Cache struct {
	mu    sync.RWMutex
	byIP  map[netip.Addr]model.Workload
	byUID map[string]model.Workload
}

// NewCache returns an empty, ready-to-use cache.
func NewCache() *Cache {
	return &Cache{
		byIP:  make(map[netip.Addr]model.Workload),
		byUID: make(map[string]model.Workload),
	}
}

// LookupIP implements Store.
func (c *Cache) LookupIP(ip netip.Addr) (model.Workload, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	w, ok := c.byIP[ip.Unmap()]
	return w, ok
}

// Upsert records (or replaces) the workload owning ip.
func (c *Cache) Upsert(ip netip.Addr, w model.Workload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byIP[ip.Unmap()] = w
}

// Delete removes ip from the cache. Deleting an absent IP is a no-op.
func (c *Cache) Delete(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byIP, ip.Unmap())
}

// UpsertUID records (or replaces) the workload owning the pod with this UID.
func (c *Cache) UpsertUID(uid string, w model.Workload) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byUID[uid] = w
}

// LookupUID returns the workload for a pod UID and true, or a zero Workload and
// false when the UID is unknown.
func (c *Cache) LookupUID(uid string) (model.Workload, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	w, ok := c.byUID[uid]
	return w, ok
}

// DeleteUID removes a pod UID from the cache. Deleting an absent UID is a no-op.
func (c *Cache) DeleteUID(uid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byUID, uid)
}

// Len returns the number of cached addresses.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byIP)
}

// WorkloadForIP resolves ip via store, returning an external-peer Workload
// (Kind == model.KindExternal, Name == the IP string) when the address is not
// known to the cluster. This is the single entry point enrichment should use
// so unknown peers always get a stable identity.
func WorkloadForIP(store Store, ip netip.Addr) model.Workload {
	if w, ok := store.LookupIP(ip); ok {
		return w
	}
	return model.Workload{Name: ip.String(), Kind: model.KindExternal}
}

// OwnerLookup resolves the controlling owner of a kubernetes object one level
// up the ownership chain (e.g. Pod -> ReplicaSet, ReplicaSet -> Deployment).
type OwnerLookup interface {
	// GetController returns the kind and name of the object's controlling
	// owner, and true, or ok=false when the object has no controller (it is
	// itself top-level).
	GetController(kind, namespace, name string) (ownerKind, ownerName string, ok bool)
}

// maxOwnerDepth caps the owner walk to defend against pathological or cyclic
// ownership graphs.
const maxOwnerDepth = 10

// ResolveTopOwner walks the owner chain upward from the given object until it
// reaches an object with no controller, and returns that top-level object as a
// Workload. Namespace is preserved from the starting object. The walk is
// bounded by maxOwnerDepth; on hitting the bound it returns the highest owner
// reached so far.
func ResolveTopOwner(kind, namespace, name string, l OwnerLookup) model.Workload {
	for range maxOwnerDepth {
		ownerKind, ownerName, ok := l.GetController(kind, namespace, name)
		if !ok {
			break
		}
		kind, name = ownerKind, ownerName
	}
	return model.Workload{Name: name, Namespace: namespace, Kind: kind}
}
