package resolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// writeCgroup lays out a fake <root>/<pid>/cgroup file.
func writeCgroup(t *testing.T, root string, pid uint32, body string) {
	t.Helper()
	dir := filepath.Join(root, formatPID(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestProcResolverLookupPID(t *testing.T) {
	root := t.TempDir()
	cache := NewCache()
	wl := model.Workload{Name: "node-exporter", Namespace: "monitoring", Kind: "DaemonSet"}
	cache.UpsertUID("3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f", wl)

	writeCgroup(t, root, 4242,
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8e3c4d_1a2b_4c5d_8e9f_0a1b2c3d4e5f.slice/cri-containerd-abc.scope")

	r := NewProcResolver(cache, root)
	got, ok := r.LookupPID(4242)
	if !ok {
		t.Fatal("expected pod resolved from PID cgroup")
	}
	if got != wl {
		t.Fatalf("LookupPID = %+v, want %+v", got, wl)
	}
}

func TestProcResolverUIDNotInCache(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, 5,
		"0::/kubepods.slice/kubepods-pod11112222_3333_4444_5555_666677778888.slice/x.scope")

	r := NewProcResolver(NewCache(), root)
	if _, ok := r.LookupPID(5); ok {
		t.Fatal("unknown UID must not resolve")
	}
}

func TestProcResolverHostProcess(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, 7, "0::/system.slice/sshd.service")

	r := NewProcResolver(NewCache(), root)
	if _, ok := r.LookupPID(7); ok {
		t.Fatal("host process (no pod segment) must not resolve")
	}
}

func TestProcResolverMissingProcEntry(t *testing.T) {
	r := NewProcResolver(NewCache(), t.TempDir())
	if _, ok := r.LookupPID(99999); ok {
		t.Fatal("missing /proc entry must not resolve")
	}
}

func TestProcResolverZeroPID(t *testing.T) {
	r := NewProcResolver(NewCache(), t.TempDir())
	if _, ok := r.LookupPID(0); ok {
		t.Fatal("PID 0 (no process context) must not resolve")
	}
}
