//go:build linux

package resolver

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appslisters "k8s.io/client-go/listers/apps/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// resyncPeriod is how often informers re-list to self-heal missed events.
const resyncPeriod = 10 * time.Minute

// Controller watches cluster pods and keeps a Cache of podIP -> top-level
// workload. It watches pods cluster-wide (not only the local node) because a
// connection's destination pod frequently lives on another node, and the
// dependency map needs both endpoints resolved.
type Controller struct {
	cache   *Cache
	factory informers.SharedInformerFactory
	pods    corelisters.PodLister
	lookup  OwnerLookup
}

// NewController builds a Controller backed by the given clientset. Call Run to
// start it and Cache to read resolved workloads.
func NewController(cs kubernetes.Interface) *Controller {
	factory := informers.NewSharedInformerFactory(cs, resyncPeriod)
	pods := factory.Core().V1().Pods().Lister()
	rs := factory.Apps().V1().ReplicaSets().Lister()

	return &Controller{
		cache:   NewCache(),
		factory: factory,
		pods:    pods,
		lookup:  &listerOwnerLookup{pods: pods, rs: rs},
	}
}

// Cache returns the IP->Workload store this controller maintains.
func (c *Controller) Cache() *Cache { return c.cache }

// Run starts the informers and blocks until ctx is cancelled. It returns an
// error if the caches fail to sync.
func (c *Controller) Run(ctx context.Context) error {
	podInformer := c.factory.Core().V1().Pods().Informer()
	// Realise the ReplicaSet informer so its lister is populated.
	_ = c.factory.Apps().V1().ReplicaSets().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onPod(obj) },
		UpdateFunc: func(_, obj any) { c.onPod(obj) },
		DeleteFunc: c.onPodDelete,
	}); err != nil {
		return fmt.Errorf("add pod event handler: %w", err)
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

// onPod indexes a pod's IPs to its resolved workload.
func (c *Controller) onPod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	// Host-network pods (e.g. the sniffer DaemonSet, kube-proxy, CNI agents)
	// report the node IP as their pod IP. Indexing that would map the node's
	// host IP — and therefore every connection to it — to a single workload,
	// producing phantom edges like dest=network-sniffer for traffic the pod
	// never received. Skip them; such node-IP traffic resolves as external.
	if pod.Spec.HostNetwork {
		return
	}
	ips := podIPs(pod)
	if len(ips) == 0 {
		return // not scheduled / no IP yet
	}
	wl := ResolveTopOwner("Pod", pod.Namespace, pod.Name, c.lookup)
	for _, ip := range ips {
		c.cache.Upsert(ip, wl)
	}
}

// onPodDelete removes a pod's IPs from the cache.
func (c *Controller) onPodDelete(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		// Handle the tombstone wrapper delivered on missed deletes.
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		pod, ok = tomb.Obj.(*corev1.Pod)
		if !ok {
			return
		}
	}
	for _, ip := range podIPs(pod) {
		c.cache.Delete(ip)
	}
}

// podIPs extracts the parseable pod IPs, preferring status.podIPs and falling
// back to status.podIP.
func podIPs(pod *corev1.Pod) []netip.Addr {
	var out []netip.Addr
	for _, pip := range pod.Status.PodIPs {
		if a, err := netip.ParseAddr(pip.IP); err == nil {
			out = append(out, a)
		}
	}
	if len(out) == 0 && pod.Status.PodIP != "" {
		if a, err := netip.ParseAddr(pod.Status.PodIP); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// listerOwnerLookup resolves controllers from informer listers, implementing
// OwnerLookup so the pure ResolveTopOwner walk can climb Pod -> ReplicaSet ->
// Deployment/Rollout. Kinds beyond Pod/ReplicaSet are treated as top-level.
type listerOwnerLookup struct {
	pods corelisters.PodLister
	rs   appslisters.ReplicaSetLister
}

func (l *listerOwnerLookup) GetController(kind, namespace, name string) (string, string, bool) {
	switch kind {
	case "Pod":
		pod, err := l.pods.Pods(namespace).Get(name)
		if err != nil {
			return "", "", false
		}
		return controllerOf(pod.GetOwnerReferences())
	case "ReplicaSet":
		set, err := l.rs.ReplicaSets(namespace).Get(name)
		if err != nil {
			return "", "", false
		}
		return controllerOf(set.GetOwnerReferences())
	default:
		return "", "", false
	}
}

// controllerOf returns the controlling owner reference, if any.
func controllerOf(refs []metav1.OwnerReference) (string, string, bool) {
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			return r.Kind, r.Name, true
		}
	}
	return "", "", false
}
