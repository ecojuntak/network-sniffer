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

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// resyncPeriod is how often informers re-list to self-heal missed events.
const resyncPeriod = 10 * time.Minute

// Controller watches cluster pods and nodes and keeps a Cache of IP ->
// workload. It watches pods cluster-wide (not only the local node) because a
// connection's destination pod frequently lives on another node, and the
// dependency map needs both endpoints resolved. Node InternalIPs are indexed
// to a Node identity so host-network and node-level traffic resolves to the
// node name instead of a bare IP.
type Controller struct {
	cache   *Cache
	factory informers.SharedInformerFactory
	pods    corelisters.PodLister
	lookup  OwnerLookup
}

// NewController builds a Controller backed by the given clientset. Call Run to
// start it and Cache to read resolved workloads.
func NewController(cs kubernetes.Interface) *Controller {
	// WithTransform trims every watched object to the fields this resolver reads
	// (see trimObject) before it enters the informer store. On a large cluster
	// each DaemonSet pod would otherwise cache full Pod/Service/EndpointSlice
	// objects cluster-wide; trimming cuts that footprint by ~an order of
	// magnitude.
	factory := informers.NewSharedInformerFactoryWithOptions(cs, resyncPeriod,
		informers.WithTransform(trimObject))
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
	nodeInformer := c.factory.Core().V1().Nodes().Informer()
	svcInformer := c.factory.Core().V1().Services().Informer()
	epInformer := c.factory.Discovery().V1().EndpointSlices().Informer()
	// Realise the ReplicaSet informer so its lister is populated.
	_ = c.factory.Apps().V1().ReplicaSets().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onPod(obj) },
		UpdateFunc: func(_, obj any) { c.onPod(obj) },
		DeleteFunc: c.onPodDelete,
	}); err != nil {
		return fmt.Errorf("add pod event handler: %w", err)
	}

	if _, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onNode(obj) },
		UpdateFunc: func(_, obj any) { c.onNode(obj) },
		DeleteFunc: c.onNodeDelete,
	}); err != nil {
		return fmt.Errorf("add node event handler: %w", err)
	}

	// Services index ClusterIP:port -> L7 protocol; EndpointSlices index the
	// backing podIP:targetPort -> L7 protocol. Both feed the same byPort store so
	// a destination resolves its application protocol whether the socket saw the
	// ClusterIP (pre-DNAT) or the pod IP (post-DNAT / Istio mesh).
	if _, err := svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onService(obj) },
		UpdateFunc: func(old, obj any) { c.onServiceUpdate(old, obj) },
		DeleteFunc: c.onServiceDelete,
	}); err != nil {
		return fmt.Errorf("add service event handler: %w", err)
	}

	if _, err := epInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.onEndpointSlice(obj) },
		UpdateFunc: func(old, obj any) { c.onEndpointSliceUpdate(old, obj) },
		DeleteFunc: c.onEndpointSliceDelete,
	}); err != nil {
		return fmt.Errorf("add endpointslice event handler: %w", err)
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

// onPod indexes a pod's IPs to its resolved workload, and indexes the pod UID
// unconditionally to back PID-based source resolution.
func (c *Controller) onPod(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	wl := ResolveTopOwner("Pod", pod.Namespace, pod.Name, c.lookup)

	// Index by UID for every pod, including host-network ones: the UID index is
	// keyed by cgroup identity, not IP, so it is the only way to attribute
	// host-network source traffic (which shares the node IP) to the exact pod.
	if uid := string(pod.UID); uid != "" {
		c.cache.UpsertUID(uid, wl)
	}

	// Host-network pods (e.g. the sniffer DaemonSet, kube-proxy, CNI agents)
	// report the node IP as their pod IP. Indexing that by IP would map the
	// node's host IP — and therefore every connection to it — to a single
	// workload, producing phantom edges like dest=network-sniffer for traffic
	// the pod never received. Skip IP indexing; their node IP resolves to a
	// Node via onNode, and their source traffic upgrades via the UID index.
	if pod.Spec.HostNetwork {
		return
	}
	ips := podIPs(pod)
	if len(ips) == 0 {
		return // not scheduled / no IP yet
	}
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
	if uid := string(pod.UID); uid != "" {
		c.cache.DeleteUID(uid)
	}
}

// onNode indexes a node's InternalIPs to a Node-kind workload. Host-network
// pods report the node IP as their pod IP and are skipped by onPod, so without
// this their source traffic resolves as a bare external IP. A node IP never
// collides with a pod IP (distinct VPC addresses, even on CGNAT clusters where
// both ranges are 100.64.0.0/10), so the two indexes share the cache safely.
func (c *Controller) onNode(obj any) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}
	wl := model.Workload{Name: node.Name, Kind: model.KindNode}
	for _, ip := range nodeInternalIPs(node) {
		c.cache.Upsert(ip, wl)
	}
}

// onNodeDelete removes a node's InternalIPs from the cache.
func (c *Controller) onNodeDelete(obj any) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		// Handle the tombstone wrapper delivered on missed deletes.
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		node, ok = tomb.Obj.(*corev1.Node)
		if !ok {
			return
		}
	}
	for _, ip := range nodeInternalIPs(node) {
		c.cache.Delete(ip)
	}
}

// nodeInternalIPs extracts the parseable NodeInternalIP addresses. Only
// InternalIP is indexed: ExternalIP is a public address in-cluster traffic
// never sources from, and DNS/HostName entries are not addresses.
func nodeInternalIPs(node *corev1.Node) []netip.Addr {
	var out []netip.Addr
	for _, addr := range node.Status.Addresses {
		if addr.Type != corev1.NodeInternalIP {
			continue
		}
		if a, err := netip.ParseAddr(addr.Address); err == nil {
			out = append(out, a)
		}
	}
	return out
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
