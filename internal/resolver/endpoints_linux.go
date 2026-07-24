//go:build linux

package resolver

import (
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
)

// onService indexes a Service's ClusterIP:port endpoints.
func (c *Controller) onService(obj any) {
	if svc, ok := obj.(*corev1.Service); ok {
		c.indexPorts(serviceEntries(svc))
	}
}

// onServiceUpdate re-indexes a changed Service, evicting the entries the old
// revision exposed that the new one no longer does.
func (c *Controller) onServiceUpdate(old, obj any) {
	oldSvc, _ := old.(*corev1.Service)
	newSvc, _ := obj.(*corev1.Service)
	c.reindexPorts(serviceEntries(oldSvc), serviceEntries(newSvc))
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

// onEndpointSlice indexes an EndpointSlice's podIP:port endpoints.
func (c *Controller) onEndpointSlice(obj any) {
	if es, ok := obj.(*discoveryv1.EndpointSlice); ok {
		c.indexPorts(endpointSliceEntries(es))
	}
}

// onEndpointSliceUpdate re-indexes a changed EndpointSlice, evicting endpoints
// the old revision exposed that the new one no longer does (pods that left).
func (c *Controller) onEndpointSliceUpdate(old, obj any) {
	oldES, _ := old.(*discoveryv1.EndpointSlice)
	newES, _ := obj.(*discoveryv1.EndpointSlice)
	c.reindexPorts(endpointSliceEntries(oldES), endpointSliceEntries(newES))
}

// onEndpointSliceDelete removes the endpoints an EndpointSlice exposed.
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
