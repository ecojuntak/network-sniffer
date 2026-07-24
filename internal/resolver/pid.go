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

// ProcResolver resolves a process ID to the kubernetes workload that owns it by
// reading the process's cgroup membership from procfs and mapping the embedded
// pod UID through a UIDStore. It exists to give host-network source traffic
// (node-exporter, kube-proxy, CNI agents) a real workload identity: those pods
// share the node IP, so IP-based resolution can only reach a Node, but the
// connecting PID's cgroup names the exact pod.
//
// The PID must be from the host PID namespace (the DaemonSet runs with
// hostPID: true) and captured in process context — the eBPF layer records it at
// tcp_connect, not at the softirq-context ESTABLISHED transition where the
// on-CPU task is unrelated.
type ProcResolver struct {
	store UIDStore
	// root is the procfs mount to read, normally "/proc"; overridable in tests.
	root string
}

// NewProcResolver builds a ProcResolver over the given UID store and procfs
// root (pass "/proc" in production).
func NewProcResolver(store UIDStore, root string) *ProcResolver {
	return &ProcResolver{store: store, root: root}
}

// LookupPID returns the workload owning pid and true, or a zero Workload and
// false when the process is gone, is not a pod member (host process), or its
// pod UID is not (yet) in the store. PID 0 never resolves: it marks the absence
// of reliable process context from the probe.
func (r *ProcResolver) LookupPID(pid uint32) (model.Workload, bool) {
	if pid == 0 {
		return model.Workload{}, false
	}
	raw, err := os.ReadFile(filepath.Join(r.root, formatPID(pid), "cgroup"))
	if err != nil {
		return model.Workload{}, false
	}
	uid, ok := ParsePodUID(string(raw))
	if !ok {
		return model.Workload{}, false
	}
	return r.store.LookupUID(uid)
}

// formatPID renders a PID as the decimal directory name procfs uses.
func formatPID(pid uint32) string {
	return strconv.FormatUint(uint64(pid), 10)
}
