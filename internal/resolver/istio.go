package resolver

import (
	"net/netip"
	"strings"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// vipBinding pairs a ServiceEntry VIP with the workload it resolves to.
type vipBinding struct {
	ip netip.Addr
	wl model.Workload
}

// parseServiceEntryVIPs extracts the (VIP -> host) bindings from the unstructured
// content of an Istio ServiceEntry. It reads two sources of addresses:
//
//   - status.addresses: the per-host VIPs istiod allocates, each an object with
//     "value" (the IP) and optionally "host". This is where auto-allocated
//     240.240.0.0/16 addresses appear.
//   - spec.addresses: user-declared VIPs for the ServiceEntry. Plain IPs are
//     bound to the first spec host; CIDRs are skipped (a range is not a peer).
//
// Each binding's workload takes the ServiceEntry namespace and Kind
// ServiceEntry, with Name set to the resolved host. Unparseable or missing
// fields are skipped rather than erroring, so a malformed object degrades to
// "no bindings" instead of failing the watch.
func parseServiceEntryVIPs(obj map[string]any) []vipBinding {
	namespace, _, _ := nestedString(obj, "metadata", "namespace")
	hosts := nestedStringSlice(obj, "spec", "hosts")
	primaryHost := ""
	if len(hosts) > 0 {
		primaryHost = hosts[0]
	}

	var out []vipBinding

	// status.addresses: [{value: "240.240.0.1", host: "db.example.com"}, ...]
	for _, entry := range nestedSlice(obj, "status", "addresses") {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		value, _ := m["value"].(string)
		ip, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		host, _ := m["host"].(string)
		if host == "" {
			host = primaryHost
		}
		if host == "" {
			continue
		}
		out = append(out, vipBinding{ip: ip, wl: model.Workload{
			Name: host, Namespace: namespace, Kind: model.KindServiceEntry,
		}})
	}

	// spec.addresses: ["10.1.2.3", "10.0.0.0/24", ...] — plain IPs only.
	if primaryHost != "" {
		for _, addr := range nestedStringSlice(obj, "spec", "addresses") {
			if strings.Contains(addr, "/") {
				continue // CIDR, not a single peer
			}
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			out = append(out, vipBinding{ip: ip, wl: model.Workload{
				Name: primaryHost, Namespace: namespace, Kind: model.KindServiceEntry,
			}})
		}
	}

	return out
}

// nestedString reads a string at the given path, returning ok=false if any
// segment is missing or the leaf is not a string.
func nestedString(obj map[string]any, path ...string) (string, bool, bool) {
	cur := obj
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return "", false, false
		}
		if i == len(path)-1 {
			s, ok := v.(string)
			return s, ok, ok
		}
		cur, ok = v.(map[string]any)
		if !ok {
			return "", false, false
		}
	}
	return "", false, false
}

// nestedSlice reads a []any at the given path, or nil if absent/mistyped.
func nestedSlice(obj map[string]any, path ...string) []any {
	cur := obj
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil
		}
		if i == len(path)-1 {
			s, _ := v.([]any)
			return s
		}
		cur, ok = v.(map[string]any)
		if !ok {
			return nil
		}
	}
	return nil
}

// nestedStringSlice reads a []string at the given path, tolerating a []any of
// strings (the shape unstructured decoding produces).
func nestedStringSlice(obj map[string]any, path ...string) []string {
	raw := nestedSlice(obj, path...)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
