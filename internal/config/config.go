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
}

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
