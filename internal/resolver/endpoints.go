package resolver

import (
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// portEntry is one resolved (endpoint, L7 protocol) pair extracted from a
// Service or EndpointSlice. A non-empty l7 means the port declares a recognized
// application protocol; entries with an empty l7 are dropped before indexing.
type portEntry struct {
	ip   netip.Addr
	port uint16
	l7   string
}

// serviceEntries builds the ClusterIP:port entries a Service exposes. Headless
// Services (ClusterIP "None"/"") contribute nothing here; their pods are still
// covered via EndpointSlices. Ports whose metadata declares no recognized L7
// protocol are skipped.
func serviceEntries(svc *corev1.Service) []portEntry {
	if svc == nil {
		return nil
	}
	ips := clusterIPs(svc)
	if len(ips) == 0 {
		return nil
	}
	var out []portEntry
	for _, p := range svc.Spec.Ports {
		l7 := model.NormalizeL7(derefString(p.AppProtocol), p.Name)
		if l7 == "" {
			continue
		}
		for _, ip := range ips {
			out = append(out, portEntry{ip: ip, port: uint16(p.Port), l7: l7})
		}
	}
	return out
}

// clusterIPs returns a Service's parseable ClusterIPs, ignoring the "None"
// sentinel used by headless Services.
func clusterIPs(svc *corev1.Service) []netip.Addr {
	raw := svc.Spec.ClusterIPs
	if len(raw) == 0 && svc.Spec.ClusterIP != "" {
		raw = []string{svc.Spec.ClusterIP}
	}
	var out []netip.Addr
	for _, s := range raw {
		if s == "" || s == corev1.ClusterIPNone {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// endpointSliceEntries builds the podIP:targetPort entries an EndpointSlice
// exposes. The slice's ports carry the name and appProtocol mirrored from the
// backing Service port, and Port is the resolved container port the socket's
// destination actually uses. Ports with a nil number or no recognized L7
// protocol are skipped.
func endpointSliceEntries(es *discoveryv1.EndpointSlice) []portEntry {
	if es == nil {
		return nil
	}
	var out []portEntry
	for _, p := range es.Ports {
		if p.Port == nil {
			continue
		}
		l7 := model.NormalizeL7(derefString(p.AppProtocol), derefString(p.Name))
		if l7 == "" {
			continue
		}
		port := uint16(*p.Port)
		for _, ep := range es.Endpoints {
			for _, addr := range ep.Addresses {
				if a, err := netip.ParseAddr(addr); err == nil {
					out = append(out, portEntry{ip: a, port: port, l7: l7})
				}
			}
		}
	}
	return out
}

// derefString returns the pointed-to string, or "" for a nil pointer.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// serviceWorkload derives the identity a Service's ClusterIP resolves to, so
// connections that target the ClusterIP (pre-DNAT, before kube-proxy/eBPF
// rewrites it to a pod IP) still name their destination. It looks up every
// endpoint address across all of the Service's EndpointSlices in store and
// collects the distinct workloads behind them:
//   - none known: ok=false, the ClusterIP stays unmapped
//   - exactly one: that workload
//   - more than one (e.g. stable + canary Deployments): a KindService identity
//     named after the Service, since no single workload owns the ClusterIP
//
// Only pod-owned workloads count; node, external and other non-pod identities
// a lookup may return are ignored. The workload is copied at index time, so
// callers must re-run this whenever the Service or its slices change.
func serviceWorkload(svc *corev1.Service, slices []*discoveryv1.EndpointSlice, store Store) (model.Workload, bool) {
	if svc == nil {
		return model.Workload{}, false
	}
	var (
		first    model.Workload
		found    bool
		multiple bool
	)
	for _, es := range slices {
		if es == nil {
			continue
		}
		for _, ep := range es.Endpoints {
			for _, addr := range ep.Addresses {
				ip, err := netip.ParseAddr(addr)
				if err != nil {
					continue
				}
				wl, ok := store.LookupIP(ip)
				if !ok || !isPodWorkload(wl) {
					continue
				}
				if !found {
					first, found = wl, true
				} else if wl != first {
					multiple = true
				}
			}
		}
	}
	switch {
	case !found:
		return model.Workload{}, false
	case multiple:
		return model.Workload{Name: svc.Name, Namespace: svc.Namespace, Kind: model.KindService}, true
	default:
		return first, true
	}
}

// isPodWorkload reports whether w is a pod-owned workload, as opposed to a
// node, external, Service or ServiceEntry identity sharing the IP cache.
func isPodWorkload(w model.Workload) bool {
	switch w.Kind {
	case model.KindExternal, model.KindNode, model.KindService, model.KindServiceEntry:
		return false
	}
	return true
}
