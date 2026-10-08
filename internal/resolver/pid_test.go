package resolver

import (
	"os"
	"path/filepath"
	"testing"
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

func TestPodUIDForPID(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, 4242,
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3f8e3c4d_1a2b_4c5d_8e9f_0a1b2c3d4e5f.slice/cri-containerd-abc.scope")

	got, ok := PodUIDForPID(root, 4242)
	if !ok {
		t.Fatal("expected pod UID resolved from PID cgroup")
	}
	if want := "3f8e3c4d-1a2b-4c5d-8e9f-0a1b2c3d4e5f"; got != want {
		t.Fatalf("PodUIDForPID = %q, want %q", got, want)
	}
}

func TestPodUIDForPIDHostProcess(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, 7, "0::/system.slice/sshd.service")

	if _, ok := PodUIDForPID(root, 7); ok {
		t.Fatal("host process (no pod segment) must not resolve")
	}
}

func TestPodUIDForPIDMissingProcEntry(t *testing.T) {
	if _, ok := PodUIDForPID(t.TempDir(), 99999); ok {
		t.Fatal("missing /proc entry must not resolve")
	}
}

func TestPodUIDForPIDZeroPID(t *testing.T) {
	if _, ok := PodUIDForPID(t.TempDir(), 0); ok {
		t.Fatal("PID 0 (no process context) must not resolve")
	}
}
