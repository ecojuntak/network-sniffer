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
