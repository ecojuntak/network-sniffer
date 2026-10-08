//go:build linux

package resolver

import (
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// endpointSliceServiceNameLabel names the Service an EndpointSlice backs.
const endpointSliceServiceNameLabel = "kubernetes.io/service-name"

// onService indexes a Service's ClusterIP:port endpoints and maps its
// ClusterIP(s) from any EndpointSlices that synced before it.
func (c *Controller) onService(obj any) {
	if svc, ok := obj.(*corev1.Service); ok {
		c.indexPorts(serviceEntries(svc))
		c.syncServiceClusterIPs(svc)
	}
}

// onServiceUpdate re-indexes a changed Service, evicting the entries the old
// revision exposed that the new one no longer does, and re-derives its
// ClusterIP mapping. A ClusterIP is normally stable for a Service's life, but a
// type change (e.g. ClusterIP <-> ExternalName) can drop or replace it, so old
// ClusterIPs absent from the new revision are evicted.
func (c *Controller) onServiceUpdate(old, obj any) {
	oldSvc, _ := old.(*corev1.Service)
	newSvc, _ := obj.(*corev1.Service)
	c.reindexPorts(serviceEntries(oldSvc), serviceEntries(newSvc))
	if newSvc == nil {
		return
	}
	if oldSvc != nil {
		kept := make(map[netip.Addr]struct{})
		for _, ip := range clusterIPs(newSvc) {
			kept[ip.Unmap()] = struct{}{}
		}
		for _, ip := range clusterIPs(oldSvc) {
			if _, ok := kept[ip.Unmap()]; !ok {
				c.cache.Delete(ip)
			}
		}
	}
	c.syncServiceClusterIPs(newSvc)
}

// onServiceDelete removes the endpoints a Service exposed and its ClusterIP
// mapping, so a deleted Service never leaves a stale ClusterIP identity behind.
func (c *Controller) onServiceDelete(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		if svc, ok = tomb.Obj.(*corev1.Service); !ok {
			return
		}
	}
	c.deletePorts(serviceEntries(svc))
	for _, ip := range clusterIPs(svc) {
		c.cache.Delete(ip)
	}
}

// onEndpointSlice indexes an EndpointSlice's podIP:port endpoints and
// re-derives its backing Service's ClusterIP mapping (pre-DNAT resolution).
func (c *Controller) onEndpointSlice(obj any) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return
	}
	c.indexPorts(endpointSliceEntries(es))
	c.syncServiceForSlice(es)
}

// onEndpointSliceUpdate re-indexes a changed EndpointSlice, evicting endpoints
// the old revision exposed that the new one no longer does (pods that left),
// and re-derives the backing Service's ClusterIP mapping.
func (c *Controller) onEndpointSliceUpdate(old, obj any) {
	oldES, _ := old.(*discoveryv1.EndpointSlice)
	newES, _ := obj.(*discoveryv1.EndpointSlice)
	c.reindexPorts(endpointSliceEntries(oldES), endpointSliceEntries(newES))
	c.syncServiceForSlice(newES)
	if oldES != nil && newES != nil &&
		oldES.Labels[endpointSliceServiceNameLabel] != newES.Labels[endpointSliceServiceNameLabel] {
		c.syncServiceForSlice(oldES)
	}
}

// onEndpointSliceDelete removes the endpoints an EndpointSlice exposed and
// re-derives its backing Service's ClusterIP mapping from the slices that
// remain. client-go removes the slice from the indexer before dispatching this
// handler, so a Service still backed by other slices keeps its mapping and one
// left with no known endpoints loses it.
func (c *Controller) onEndpointSliceDelete(obj any) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		if es, ok = tomb.Obj.(*discoveryv1.EndpointSlice); !ok {
			return
		}
	}
	c.deletePorts(endpointSliceEntries(es))
	c.syncServiceForSlice(es)
}

// indexPorts writes every entry into the port cache.
func (c *Controller) indexPorts(entries []portEntry) {
	for _, e := range entries {
		c.cache.UpsertPort(e.ip, e.port, e.l7)
	}
}

// deletePorts removes every entry from the port cache.
func (c *Controller) deletePorts(entries []portEntry) {
	for _, e := range entries {
		c.cache.DeletePort(e.ip, e.port)
	}
}

// reindexPorts applies the new entries then evicts stale ones: keys present in
// old but absent from new. New entries are written first so a lookup racing the
// update never observes a gap for a key that survives the change.
func (c *Controller) reindexPorts(old, updated []portEntry) {
	c.indexPorts(updated)
	kept := make(map[portKey]struct{}, len(updated))
	for _, e := range updated {
		kept[portKey{ip: e.ip.Unmap(), port: e.port}] = struct{}{}
	}
	for _, e := range old {
		if _, ok := kept[portKey{ip: e.ip.Unmap(), port: e.port}]; !ok {
			c.cache.DeletePort(e.ip, e.port)
		}
	}
}

// syncServiceForSlice re-derives the ClusterIP mapping of the Service an
// EndpointSlice backs, found via its `kubernetes.io/service-name` label. A
// slice with no such label, or whose Service is not (yet) in the lister, is a
// no-op: the Service's own add handler covers the latter.
func (c *Controller) syncServiceForSlice(es *discoveryv1.EndpointSlice) {
	if es == nil {
		return
	}
	serviceName := es.Labels[endpointSliceServiceNameLabel]
	if serviceName == "" {
		return
	}
	svc, err := c.services.Services(es.Namespace).Get(serviceName)
	if err != nil {
		return
	}
	c.syncServiceClusterIPs(svc)
}

// syncServiceClusterIPs maps a Service's ClusterIP(s) to the identity derived
// from all of its current EndpointSlices (see serviceWorkload), or evicts them
// when no backing endpoint resolves. Recomputing from every slice keeps the
// mapping correct when a Service spans several slices or several workloads,
// and makes the operation idempotent for any event order. Headless Services
// have no ClusterIP and are a no-op.
func (c *Controller) syncServiceClusterIPs(svc *corev1.Service) {
	if svc == nil {
		return
	}
	ips := clusterIPs(svc)
	if len(ips) == 0 {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels: map[string]string{endpointSliceServiceNameLabel: svc.Name},
	})
	if err != nil {
		return
	}
	slices, err := c.endpointSlices.EndpointSlices(svc.Namespace).List(selector)
	if err != nil {
		return
	}
	wl, ok := serviceWorkload(svc, slices, c.cache)
	for _, ip := range ips {
		if ok {
			c.cache.Upsert(ip, wl)
		} else {
			c.cache.Delete(ip)
		}
	}
}

// reindexAllClusterIPs (re)derives the ClusterIP mapping for every Service.
// Called once after every informer (including Pods) has completed its initial
// sync, so pod IPs are already cached when ClusterIPs are mapped to them.
func (c *Controller) reindexAllClusterIPs() {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		return
	}
	for _, svc := range services {
		c.syncServiceClusterIPs(svc)
	}
}
