//go:build linux

package resolver

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

// istioGroup and istioResource identify the Istio ServiceEntry CRD.
const (
	istioGroup    = "networking.istio.io"
	istioResource = "serviceentries"
)

// IstioController watches Istio ServiceEntry objects and indexes their VIPs
// (spec addresses and istiod's auto-allocated 240.240.0.0/16 status addresses)
// into the shared Cache, so a destination IP that is a ServiceEntry VIP resolves
// to the external host name instead of a bare IP. It uses a dynamic informer so
// the sniffer takes no compile-time dependency on the Istio API packages, and
// is only started when Istio resolution is enabled in config.
type IstioController struct {
	cache   *Cache
	factory dynamicinformer.DynamicSharedInformerFactory
	gvr     schema.GroupVersionResource
}

// NewIstioController builds a controller over the given dynamic client. An empty
// apiVersion falls back to a sane default so a misconfigured version does not
// silently watch nothing.
func NewIstioController(dc dynamic.Interface, c *Cache, apiVersion string) *IstioController {
	if apiVersion == "" {
		apiVersion = "v1beta1"
	}
	return &IstioController{
		cache:   c,
		factory: dynamicinformer.NewDynamicSharedInformerFactory(dc, resyncPeriod),
		gvr:     schema.GroupVersionResource{Group: istioGroup, Version: apiVersion, Resource: istioResource},
	}
}

// Run starts the ServiceEntry informer and blocks until ctx is cancelled.
func (c *IstioController) Run(ctx context.Context) error {
	informer := c.factory.ForResource(c.gvr).Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onServiceEntry(obj) },
		UpdateFunc: func(_, obj any) { c.onServiceEntry(obj) },
		DeleteFunc: c.onServiceEntryDelete,
	}); err != nil {
		return fmt.Errorf("add serviceentry event handler: %w", err)
	}

	c.factory.Start(ctx.Done())
	for typ, ok := range c.factory.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return fmt.Errorf("informer cache for %v failed to sync", typ)
		}
	}

	<-ctx.Done()
	return ctx.Err()
}

// onServiceEntry indexes every VIP the ServiceEntry exposes.
func (c *IstioController) onServiceEntry(obj any) {
	u, ok := asUnstructured(obj)
	if !ok {
		return
	}
	for _, b := range parseServiceEntryVIPs(u.Object) {
		c.cache.Upsert(b.ip, b.wl)
	}
}

// onServiceEntryDelete removes the VIPs the ServiceEntry exposed.
func (c *IstioController) onServiceEntryDelete(obj any) {
	u, ok := asUnstructured(obj)
	if !ok {
		return
	}
	for _, b := range parseServiceEntryVIPs(u.Object) {
		c.cache.Delete(b.ip)
	}
}

// asUnstructured unwraps an informer object, tolerating the tombstone wrapper
// delivered on missed deletes.
func asUnstructured(obj any) (*unstructured.Unstructured, bool) {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u, true
	}
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		u, ok := tomb.Obj.(*unstructured.Unstructured)
		return u, ok
	}
	return nil, false
}
