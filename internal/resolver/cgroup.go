package resolver

import (
	"regexp"
	"strings"
)

// podUIDPattern matches the kubernetes pod UID embedded in a cgroup path. The
// kubelet writes the pod's cgroup under a `pod<UID>` segment; the UID appears
// in one of three forms depending on the cgroup driver and runtime:
//
//	systemd:   pod<8>_<4>_<4>_<4>_<12>   (dashes escaped to underscores)
//	cgroupfs:  pod<8>-<4>-<4>-<4>-<12>   (canonical dashed UUID)
//	compact:   pod<32 hex>              (no separators, some runtimes)
//
// The pattern captures the raw UID body after `pod`; normalisePodUID then
// canonicalises it to a lowercase dashed UUID.
var podUIDPattern = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}|[0-9a-fA-F]{32})`)

// ParsePodUID extracts the kubernetes pod UID from the contents of a
// /proc/<pid>/cgroup file, returning the canonical lowercase dashed UUID and
// true. It returns ok=false for host processes and any cgroup path with no
// recognisable pod segment. The whole file is scanned so it works for both the
// single-line cgroup v2 layout and the multi-line v1 layout.
func ParsePodUID(cgroup string) (string, bool) {
	m := podUIDPattern.FindStringSubmatch(cgroup)
	if m == nil {
		return "", false
	}
	return normalisePodUID(m[1]), true
}

// normalisePodUID turns a raw pod-UID body (underscore-escaped, dashed, or
// separator-free) into a canonical lowercase 8-4-4-4-12 dashed UUID.
func normalisePodUID(raw string) string {
	s := strings.ToLower(strings.ReplaceAll(raw, "_", "-"))
	if !strings.Contains(s, "-") && len(s) == 32 {
		return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
	}
	return s
}
