//go:build linux

package resolver

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// trimObject is the informer TransformFunc that shrinks every watched object to
// only the fields this resolver reads before it is stored in the shared cache.
//
// On a large cluster each DaemonSet pod holds a full in-memory copy of every
// Pod/Node/Service/EndpointSlice/ReplicaSet. The bulk of that footprint is data
// this program never touches: managedFields (often 30-50% of an object),
// annotations, labels, env, container specs, conditions, volumes. Stripping it
// at ingestion cuts informer memory by roughly an order of magnitude without
// changing any resolution behaviour.
//
// Every returned object keeps exactly the fields consumed elsewhere:
//   - Pod: namespace/name/UID + ownerRefs (owner walk), hostNetwork, pod IPs
//   - ReplicaSet: namespace/name + ownerRefs (owner walk continuation)
//   - Node: name + addresses (InternalIP indexing)
//   - Service: namespace/name + ClusterIP(s) + ports (L7 port index)
//   - EndpointSlice: namespace/name + ports + endpoint addresses (L7 port index)
//
// Tombstone (cache.DeletedFinalStateUnknown) values are passed through: the
// delete handlers unwrap them, and their inner object was already trimmed on the
// way in. Unknown types are returned unchanged.
func trimObject(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Pod:
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       o.Namespace,
				Name:            o.Name,
				UID:             o.UID,
				OwnerReferences: o.OwnerReferences,
			},
			Spec:   corev1.PodSpec{HostNetwork: o.Spec.HostNetwork},
			Status: corev1.PodStatus{PodIP: o.Status.PodIP, PodIPs: o.Status.PodIPs},
		}, nil

	case *appsv1.ReplicaSet:
		return &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       o.Namespace,
				Name:            o.Name,
				OwnerReferences: o.OwnerReferences,
			},
		}, nil

	case *corev1.Node:
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: o.Name},
			Status:     corev1.NodeStatus{Addresses: o.Status.Addresses},
		}, nil

	case *corev1.Service:
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: o.Namespace, Name: o.Name},
			Spec: corev1.ServiceSpec{
				ClusterIP:  o.Spec.ClusterIP,
				ClusterIPs: o.Spec.ClusterIPs,
				Ports:      o.Spec.Ports,
			},
		}, nil

	case *discoveryv1.EndpointSlice:
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: o.Namespace, Name: o.Name},
			Ports:      o.Ports,
			Endpoints:  trimEndpoints(o.Endpoints),
		}, nil
	}

	return obj, nil
}

// trimEndpoints keeps only the addresses of each endpoint — the sole field
// endpointSliceEntries reads — dropping targetRef, nodeName, conditions, hints
// and zone metadata that would otherwise be retained per backing pod.
func trimEndpoints(in []discoveryv1.Endpoint) []discoveryv1.Endpoint {
	if len(in) == 0 {
		return nil
	}
	out := make([]discoveryv1.Endpoint, len(in))
	for i, ep := range in {
		out[i] = discoveryv1.Endpoint{Addresses: ep.Addresses}
	}
	return out
}

// transformOption is the factory option that registers trimObject on every
// informer the controller creates. Kept as a named var so the wiring in
// NewController reads clearly and the transform is exercised in tests.
var _ cache.TransformFunc = trimObject
