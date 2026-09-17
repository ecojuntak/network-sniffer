//go:build linux

package resolver

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// endpointSliceServiceNameLabel names the Service an EndpointSlice backs.
const endpointSliceServiceNameLabel = "kubernetes.io/service-name"

// onService indexes a Service's ClusterIP:port endpoints.
func (c *Controller) onService(obj any) {
	if svc, ok := obj.(*corev1.Service); ok {
		c.indexPorts(serviceEntries(svc))
	}
}

// onServiceUpdate re-indexes a changed Service, evicting the entries the old
// revision exposed that the new one no longer does, and refreshes its
// ClusterIP -> pod IP mapping (a ClusterIP is stable for a Service's life, but
// this also covers the case where an update reveals the Service to the
// resolver for the first time relative to its EndpointSlices).
func (c *Controller) onServiceUpdate(old, obj any) {
	oldSvc, _ := old.(*corev1.Service)
	newSvc, _ := obj.(*corev1.Service)
	c.reindexPorts(serviceEntries(oldSvc), serviceEntries(newSvc))
	if newSvc != nil {
		c.indexClusterIPsForService(newSvc)
	}
}

// onServiceDelete removes the endpoints a Service exposed.
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
}

// onEndpointSlice indexes an EndpointSlice's podIP:port endpoints and its
// backing Service's ClusterIP -> pod IP mapping (pre-DNAT resolution).
func (c *Controller) onEndpointSlice(obj any) {
	es, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return
	}
	c.indexPorts(endpointSliceEntries(es))
	c.indexClusterIPsFromEndpointSlice(es)
}

// onEndpointSliceUpdate re-indexes a changed EndpointSlice, evicting endpoints
// the old revision exposed that the new one no longer does (pods that left),
// and refreshes the ClusterIP -> pod IP mapping.
func (c *Controller) onEndpointSliceUpdate(old, obj any) {
	oldES, _ := old.(*discoveryv1.EndpointSlice)
	newES, _ := obj.(*discoveryv1.EndpointSlice)
	c.reindexPorts(endpointSliceEntries(oldES), endpointSliceEntries(newES))
	c.indexClusterIPsFromEndpointSlice(newES)
}

// onEndpointSliceDelete removes the endpoints an EndpointSlice exposed and its
// backing Service's ClusterIP mapping.
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
	c.deleteClusterIPsFromEndpointSlice(es)
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

// indexClusterIPsFromEndpointSlice maps a Service's ClusterIP(s) to a backing
// pod IP, using the EndpointSlice's `kubernetes.io/service-name` label to find
// the Service. The pod IP resolves to its workload through the normal pod-IP
// cache lookup, so a connection that targets the ClusterIP pre-DNAT still
// resolves instead of surfacing as a bare, unresolved ClusterIP.
func (c *Controller) indexClusterIPsFromEndpointSlice(es *discoveryv1.EndpointSlice) {
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
	for _, e := range endpointSliceClusterIPEntries(es, svc) {
		if wl, ok := c.cache.LookupIP(e.podIP); ok {
			c.cache.Upsert(e.clusterIP, wl)
		}
	}
}

// deleteClusterIPsFromEndpointSlice removes the ClusterIP mappings for the
// EndpointSlice's backing Service.
func (c *Controller) deleteClusterIPsFromEndpointSlice(es *discoveryv1.EndpointSlice) {
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
	for _, ip := range clusterIPs(svc) {
		c.cache.Delete(ip)
	}
}

// indexClusterIPsForService (re)indexes ClusterIP -> pod IP mappings for every
// EndpointSlice currently backing svc. Called when a Service is added or
// updated to cover the race where its EndpointSlices arrived first.
func (c *Controller) indexClusterIPsForService(svc *corev1.Service) {
	if svc == nil {
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
	for _, es := range slices {
		c.indexClusterIPsFromEndpointSlice(es)
	}
}

// reindexAllClusterIPs (re)indexes ClusterIP -> pod IP mappings for every
// Service. Called once after every informer (including Pods) has completed
// its initial sync, so pod IPs are already cached when ClusterIPs are mapped
// to them.
func (c *Controller) reindexAllClusterIPs() {
	services, err := c.services.List(labels.Everything())
	if err != nil {
		return
	}
	for _, svc := range services {
		c.indexClusterIPsForService(svc)
	}
}
