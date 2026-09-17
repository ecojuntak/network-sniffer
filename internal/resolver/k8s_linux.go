//go:build linux

package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	appslisters "k8s.io/client-go/listers/apps/v1"
	batchlisters "k8s.io/client-go/listers/batch/v1"
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
	cache      *Cache
	factory    informers.SharedInformerFactory
	pods       corelisters.PodLister
	lookup     OwnerLookup
	logger     *slog.Logger
	syncedChan chan struct{} // closed once every informer has completed its initial sync
}

// NewController builds a Controller backed by the given clientset. Call Run to
// start it and Cache to read resolved workloads. logger is optional (nil
// disables logging) and is used to surface owner-lookup misses that would
// otherwise silently leak an intermediate (hash-suffixed) name as a workload
// identity.
func NewController(cs kubernetes.Interface, logger *slog.Logger) *Controller {
	// WithTransform trims every watched object to the fields this resolver reads
	// (see trimObject) before it enters the informer store. On a large cluster
	// each DaemonSet pod would otherwise cache full Pod/Service/EndpointSlice
	// objects cluster-wide; trimming cuts that footprint by ~an order of
	// magnitude.
	factory := informers.NewSharedInformerFactoryWithOptions(cs, resyncPeriod,
		informers.WithTransform(trimObject))
	pods := factory.Core().V1().Pods().Lister()
	rs := factory.Apps().V1().ReplicaSets().Lister()
	jobs := factory.Batch().V1().Jobs().Lister()

	return &Controller{
		cache:      NewCache(),
		factory:    factory,
		pods:       pods,
		lookup:     &listerOwnerLookup{pods: pods, rs: rs, jobs: jobs, logger: logger},
		logger:     logger,
		syncedChan: make(chan struct{}),
	}
}

// Cache returns the IP->Workload store this controller maintains.
func (c *Controller) Cache() *Cache { return c.cache }

// WaitForSync blocks until every informer has completed its initial sync.
// Call this before processing eBPF events so the resolver never attributes a
// pod to an intermediate ReplicaSet/Job name because its owning Deployment or
// CronJob hadn't synced yet.
func (c *Controller) WaitForSync() {
	<-c.syncedChan
}

// Run starts the informers and blocks until ctx is cancelled. It returns an
// error if the caches fail to sync.
//
// Informers start in two phases to close a sync-order race: ownership
// informers (ReplicaSet, Job) sync first, then Pod/Node/Service/EndpointSlice
// sync second. Without this ordering, a Pod add event can fire before the
// ReplicaSet/Job cache is populated, so ResolveTopOwner returns the
// intermediate ReplicaSet/Job name instead of the top-level
// Deployment/CronJob. StatefulSet and DaemonSet need no informer: they are
// top-level workloads, and ResolveTopOwner stops at them from ownerReferences
// alone.
func (c *Controller) Run(ctx context.Context) error {
	podInformer := c.factory.Core().V1().Pods().Informer()
	nodeInformer := c.factory.Core().V1().Nodes().Informer()
	svcInformer := c.factory.Core().V1().Services().Informer()
	epInformer := c.factory.Discovery().V1().EndpointSlices().Informer()
	rsInformer := c.factory.Apps().V1().ReplicaSets().Informer()
	jobInformer := c.factory.Batch().V1().Jobs().Informer()

	// Phase 1: register no-op handlers on the ownership informers — they are
	// read only via lister during the owner-chain walk, never reacted to — and
	// sync them before any Pod event can be processed.
	if _, err := rsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) {},
		UpdateFunc: func(any, any) {},
		DeleteFunc: func(any) {},
	}); err != nil {
		return fmt.Errorf("add replicaset event handler: %w", err)
	}
	if _, err := jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) {},
		UpdateFunc: func(any, any) {},
		DeleteFunc: func(any) {},
	}); err != nil {
		return fmt.Errorf("add job event handler: %w", err)
	}

	go rsInformer.Run(ctx.Done())
	go jobInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), rsInformer.HasSynced, jobInformer.HasSynced) {
		return fmt.Errorf("replicaset/job informers failed to sync")
	}

	// Phase 2: ownership data is ready, so Pod add events now always resolve to
	// the correct top-level workload.
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

	go podInformer.Run(ctx.Done())
	go nodeInformer.Run(ctx.Done())
	go svcInformer.Run(ctx.Done())
	go epInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		podInformer.HasSynced, nodeInformer.HasSynced, svcInformer.HasSynced, epInformer.HasSynced,
	) {
		return fmt.Errorf("pod/node/service/endpointslice informers failed to sync")
	}

	close(c.syncedChan)

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
// OwnerLookup so the pure ResolveTopOwner walk can climb ownership chains:
//   - Pod -> ReplicaSet -> Deployment/Rollout (ReplicaSet is intermediate)
//   - Pod -> Job -> CronJob (Job is intermediate)
//   - Pod -> StatefulSet / DaemonSet (top-level, no intermediate)
//
// Only intermediate kinds (ReplicaSet, Job) need cases in GetController;
// top-level kinds fall through to the default case.
type listerOwnerLookup struct {
	pods   corelisters.PodLister
	rs     appslisters.ReplicaSetLister
	jobs   batchlisters.JobLister
	logger *slog.Logger // optional; nil disables logging
}

// logMiss reports a failed owner lookup: the walk stops early and the
// intermediate (hash-suffixed) name leaks out as the workload identity, so the
// miss must be observable rather than silent. Rare: Run awaits ownership
// informer sync before pods are processed, so misses mean a deleted owner or
// a genuine cache gap.
func (l *listerOwnerLookup) logMiss(kind, namespace, name string, err error) {
	if l.logger != nil {
		l.logger.Warn("owner lookup failed, resolving to intermediate identity",
			slog.String("kind", kind),
			slog.String("namespace", namespace),
			slog.String("name", name),
			slog.Any("err", err))
	}
}

func (l *listerOwnerLookup) GetController(kind, namespace, name string) (string, string, bool) {
	switch kind {
	case "Pod":
		pod, err := l.pods.Pods(namespace).Get(name)
		if err != nil {
			l.logMiss(kind, namespace, name, err)
			return "", "", false
		}
		return controllerOf(pod.GetOwnerReferences())
	case "ReplicaSet":
		set, err := l.rs.ReplicaSets(namespace).Get(name)
		if err != nil {
			l.logMiss(kind, namespace, name, err)
			return "", "", false
		}
		return controllerOf(set.GetOwnerReferences())
	case "Job":
		job, err := l.jobs.Jobs(namespace).Get(name)
		if err != nil {
			l.logMiss(kind, namespace, name, err)
			return "", "", false
		}
		return controllerOf(job.GetOwnerReferences())
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
