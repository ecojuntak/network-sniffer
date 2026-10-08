package resolver

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// UIDStore looks up the workload owning a pod by its UID. Cache satisfies it.
type UIDStore interface {
	LookupUID(uid string) (model.Workload, bool)
}

// PodUIDForPID returns the UID of the pod owning pid by reading the process's
// cgroup membership from procfs under root (pass "/proc" in production). It
// exists to give host-network source traffic (node-exporter, kube-proxy, CNI
// agents) a real workload identity: those pods share the node IP, so IP-based
// resolution can only reach a Node, but the connecting PID's cgroup names the
// exact pod.
//
// It runs on the node (the collector): the PID must be from the host PID
// namespace (the DaemonSet runs with hostPID: true) and captured in process
// context — the eBPF layer records it at tcp_connect, not at the
// softirq-context ESTABLISHED transition where the on-CPU task is unrelated.
// The resulting UID travels to the processor, which maps it through a
// UIDStore.
//
// It returns false when the process is gone, is not a pod member (host
// process), or pid is 0, which marks the absence of reliable process context
// from the probe.
func PodUIDForPID(root string, pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	raw, err := os.ReadFile(filepath.Join(root, formatPID(pid), "cgroup"))
	if err != nil {
		return "", false
	}
	return ParsePodUID(string(raw))
}

// formatPID renders a PID as the decimal directory name procfs uses.
func formatPID(pid uint32) string {
	return strconv.FormatUint(uint64(pid), 10)
}
