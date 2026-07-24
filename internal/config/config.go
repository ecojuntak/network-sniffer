// Package config loads the sniffer's optional runtime configuration from a
// YAML file, typically mounted from a ConfigMap. Everything in it is optional;
// a missing configuration means "no overrides".
package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Config is the parsed runtime configuration.
type Config struct {
	// Ignore lists "<namespace>/<workload>" glob patterns whose edges are
	// dropped before emission. See internal/ignore for the pattern grammar.
	Ignore []string `json:"ignore"`

	// Istio configures resolution of Istio ServiceEntry VIPs (including the
	// auto-allocated 240.240.0.0/16 addresses) to their external host name.
	Istio IstioConfig `json:"istio"`
}

// IstioConfig toggles and tunes Istio ServiceEntry resolution. It is disabled
// by default so clusters without Istio need no CRD, RBAC or extra watches.
type IstioConfig struct {
	// Enabled turns on the ServiceEntry watch. Requires the CRD and the
	// serviceentries get/list/watch RBAC (see deploy/rbac.yaml).
	Enabled bool `json:"enabled"`
	// APIVersion overrides the ServiceEntry API version to watch. Defaults to
	// DefaultIstioAPIVersion when empty.
	APIVersion string `json:"apiVersion"`
}

// DefaultIstioAPIVersion is the ServiceEntry API version watched when
// IstioConfig.APIVersion is empty.
const DefaultIstioAPIVersion = "v1beta1"

// Load reads and parses the config file at path. An empty path returns a zero
// Config (the file is optional). A non-empty path that cannot be read or parsed
// is an error, so a misconfigured mount fails loudly rather than silently
// disabling filtering.
func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}
