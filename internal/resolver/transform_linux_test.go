//go:build linux

package resolver

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// bloat is the noise every trimmed type must shed: heavy metadata this resolver
// never reads but client-go would otherwise retain per object.
func bloat() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Annotations:   map[string]string{"kubectl.kubernetes.io/last-applied-configuration": "big"},
		Labels:        map[string]string{"a": "1", "b": "2"},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}, {Manager: "kube-controller-manager"}},
		Finalizers:    []string{"x"},
	}
}

func assertStripped(t *testing.T, m metav1.ObjectMeta) {
	t.Helper()
	if m.Annotations != nil || m.Labels != nil || m.ManagedFields != nil || m.Finalizers != nil {
		t.Errorf("heavy metadata not stripped: %+v", m)
	}
}

func TestTrimPodKeepsResolutionFieldsDropsBloat(t *testing.T) {
	meta := bloat()
	meta.Namespace, meta.Name, meta.UID = "ns", "web-abc", "uid-1"
	meta.OwnerReferences = []metav1.OwnerReference{ctrlRef("ReplicaSet", "web-rs")}

	in := &corev1.Pod{
		ObjectMeta: meta,
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "app", Image: "img", Env: []corev1.EnvVar{{Name: "BIG"}}}},
		},
		Status: corev1.PodStatus{
			PodIP:      "10.0.0.1",
			PodIPs:     []corev1.PodIP{{IP: "10.0.0.1"}},
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady}},
		},
	}

	out, err := trimObject(in)
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	got, ok := out.(*corev1.Pod)
	if !ok {
		t.Fatalf("want *corev1.Pod, got %T", out)
	}

	if got.Namespace != "ns" || got.Name != "web-abc" || got.UID != "uid-1" {
		t.Errorf("identity fields lost: %+v", got.ObjectMeta)
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "web-rs" {
		t.Errorf("owner refs lost: %+v", got.OwnerReferences)
	}
	if !got.Spec.HostNetwork {
		t.Error("hostNetwork lost")
	}
	if got.Status.PodIP != "10.0.0.1" || len(got.Status.PodIPs) != 1 {
		t.Errorf("pod IPs lost: %+v", got.Status)
	}
	if len(got.Spec.Containers) != 0 || len(got.Status.Conditions) != 0 {
		t.Error("heavy spec/status not stripped")
	}
	assertStripped(t, got.ObjectMeta)
}

func TestTrimReplicaSetKeepsOwnerRefs(t *testing.T) {
	meta := bloat()
	meta.Namespace, meta.Name = "ns", "web-rs"
	meta.OwnerReferences = []metav1.OwnerReference{ctrlRef("Deployment", "web")}

	out, err := trimObject(&appsv1.ReplicaSet{
		ObjectMeta: meta,
		Spec:       appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}},
	})
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	got := out.(*appsv1.ReplicaSet)
	if got.Name != "web-rs" || len(got.OwnerReferences) != 1 || got.OwnerReferences[0].Name != "web" {
		t.Errorf("owner chain lost: %+v", got.ObjectMeta)
	}
	if len(got.Spec.Template.Spec.Containers) != 0 {
		t.Error("template not stripped")
	}
	assertStripped(t, got.ObjectMeta)
}

func TestTrimNodeKeepsAddresses(t *testing.T) {
	meta := bloat()
	meta.Name = "node-1"
	out, err := trimObject(&corev1.Node{
		ObjectMeta: meta,
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "172.16.0.1"}},
			Images:    []corev1.ContainerImage{{Names: []string{"big"}}},
		},
	})
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	got := out.(*corev1.Node)
	if got.Name != "node-1" || len(got.Status.Addresses) != 1 || got.Status.Addresses[0].Address != "172.16.0.1" {
		t.Errorf("node addresses lost: %+v", got.Status.Addresses)
	}
	if len(got.Status.Images) != 0 {
		t.Error("node images not stripped")
	}
	assertStripped(t, got.ObjectMeta)
}

func TestTrimServiceKeepsClusterIPAndPorts(t *testing.T) {
	meta := bloat()
	meta.Namespace, meta.Name = "ns", "svc"
	out, err := trimObject(&corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.1",
			ClusterIPs: []string{"10.96.0.1"},
			Ports:      []corev1.ServicePort{{Name: "grpc", Port: 8080}},
			Selector:   map[string]string{"app": "x"},
		},
	})
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	got := out.(*corev1.Service)
	if got.Spec.ClusterIP != "10.96.0.1" || len(got.Spec.ClusterIPs) != 1 || len(got.Spec.Ports) != 1 {
		t.Errorf("service port fields lost: %+v", got.Spec)
	}
	if got.Spec.Selector != nil {
		t.Error("selector not stripped")
	}
	assertStripped(t, got.ObjectMeta)
}

func TestTrimEndpointSliceKeepsPortsAndAddresses(t *testing.T) {
	meta := bloat()
	meta.Namespace, meta.Name = "ns", "svc-abc"
	node := "node-1"
	out, err := trimObject(&discoveryv1.EndpointSlice{
		ObjectMeta: meta,
		Ports:      []discoveryv1.EndpointPort{{Name: ptr.To("http"), Port: ptr.To[int32](8080)}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.5"},
			NodeName:  &node,
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "p"},
		}},
	})
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	got := out.(*discoveryv1.EndpointSlice)
	if len(got.Ports) != 1 || len(got.Endpoints) != 1 || len(got.Endpoints[0].Addresses) != 1 {
		t.Errorf("endpoint fields lost: %+v", got)
	}
	if got.Endpoints[0].NodeName != nil || got.Endpoints[0].TargetRef != nil {
		t.Error("endpoint metadata not stripped")
	}
	assertStripped(t, got.ObjectMeta)
}

func TestTrimPassesUnknownTypesThrough(t *testing.T) {
	in := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm"}}
	out, err := trimObject(in)
	if err != nil {
		t.Fatalf("trimObject: %v", err)
	}
	if out != in {
		t.Error("unknown type should pass through unchanged")
	}
}
