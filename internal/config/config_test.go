package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadIgnoreList(t *testing.T) {
	p := writeConfig(t, `
# Workloads to exclude from the dependency map.
ignore:
  - "kube-system/*"
  - "*/istiod"
  - "/ip-*"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"kube-system/*", "*/istiod", "/ip-*"}
	if len(cfg.Ignore) != len(want) {
		t.Fatalf("Ignore = %v, want %v", cfg.Ignore, want)
	}
	for i := range want {
		if cfg.Ignore[i] != want[i] {
			t.Fatalf("Ignore[%d] = %q, want %q", i, cfg.Ignore[i], want[i])
		}
	}
}

func TestLoadIstioToggle(t *testing.T) {
	p := writeConfig(t, `
istio:
  enabled: true
  apiVersion: v1
ignore:
  - "kube-system/*"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Istio.Enabled {
		t.Fatal("Istio.Enabled = false, want true")
	}
	if cfg.Istio.APIVersion != "v1" {
		t.Fatalf("Istio.APIVersion = %q, want v1", cfg.Istio.APIVersion)
	}
}

// Istio defaults to disabled when the section is absent.
func TestLoadIstioDefaultDisabled(t *testing.T) {
	p := writeConfig(t, "ignore: []\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Istio.Enabled {
		t.Fatal("Istio.Enabled = true, want false by default")
	}
}

// An empty path yields an empty config, not an error: the ignore list is
// optional.
func TestLoadEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if len(cfg.Ignore) != 0 {
		t.Fatalf("Ignore = %v, want empty", cfg.Ignore)
	}
}

// A configured but missing path is an error: a typo in the mount must not be
// silently ignored.
func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("Load(missing) = nil error, want error")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	p := writeConfig(t, "ignore: [unclosed")
	if _, err := Load(p); err == nil {
		t.Fatal("Load(invalid) = nil error, want error")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	p := writeConfig(t, "")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load(empty file): %v", err)
	}
	if len(cfg.Ignore) != 0 {
		t.Fatalf("Ignore = %v, want empty", cfg.Ignore)
	}
}
