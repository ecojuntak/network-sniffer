// Package config loads the sniffer's optional runtime configuration from a
// YAML file, typically mounted from a ConfigMap. Everything in it is optional;
// a missing configuration means "no overrides".
package config

import (
	"errors"
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

	// Emit selects where emitted service-call edges are written.
	Emit EmitConfig `json:"emit"`
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

// EmitConfig selects the output sinks. With no emit section, edges go to
// stdout only.
type EmitConfig struct {
	Stdout StdoutConfig `json:"stdout"`
	Kafka  KafkaConfig  `json:"kafka"`
}

// StdoutConfig toggles the JSON log-line sink on stdout.
type StdoutConfig struct {
	// Enabled defaults to true when unset, so existing configs keep logging.
	Enabled *bool `json:"enabled"`
}

// StdoutEnabled reports whether the stdout sink is on (default true).
func (e EmitConfig) StdoutEnabled() bool {
	return e.Stdout.Enabled == nil || *e.Stdout.Enabled
}

// KafkaConfig configures the Kafka sink. Each edge is produced as one JSON
// record carrying the same fields as the stdout log line.
type KafkaConfig struct {
	Enabled bool `json:"enabled"`
	// Brokers are the seed brokers, "host:port".
	Brokers []string `json:"brokers"`
	Topic   string   `json:"topic"`
	// ClientID defaults to DefaultKafkaClientID when empty.
	ClientID string          `json:"clientID"`
	TLS      KafkaTLSConfig  `json:"tls"`
	SASL     KafkaSASLConfig `json:"sasl"`
}

// KafkaTLSConfig enables TLS to the brokers.
type KafkaTLSConfig struct {
	Enabled bool `json:"enabled"`
	// CAFile is a PEM bundle used instead of the system roots when set.
	CAFile             string `json:"caFile"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// KafkaSASLConfig enables SASL authentication. An empty Mechanism disables it.
type KafkaSASLConfig struct {
	// Mechanism is one of the SASLMechanism* constants.
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	// Password is overridden by the KafkaPasswordEnv environment variable when
	// that is set, so the secret can come from a Kubernetes Secret instead of
	// the ConfigMap.
	Password string `json:"password"`
}

// Supported SASL mechanisms.
const (
	SASLMechanismPlain       = "PLAIN"
	SASLMechanismScramSHA256 = "SCRAM-SHA-256"
	SASLMechanismScramSHA512 = "SCRAM-SHA-512"
)

// DefaultKafkaClientID is the Kafka client ID used when none is configured.
const DefaultKafkaClientID = "network-sniffer-processor"

// KafkaPasswordEnv names the environment variable that overrides
// emit.kafka.sasl.password.
const KafkaPasswordEnv = "KAFKA_SASL_PASSWORD"

// Validate reports a misconfigured emit section.
func (e EmitConfig) Validate() error {
	if !e.StdoutEnabled() && !e.Kafka.Enabled {
		return errors.New("emit: no sink enabled")
	}
	if !e.Kafka.Enabled {
		return nil
	}
	k := e.Kafka
	if len(k.Brokers) == 0 {
		return errors.New("emit.kafka: brokers is required")
	}
	if k.Topic == "" {
		return errors.New("emit.kafka: topic is required")
	}
	switch k.SASL.Mechanism {
	case "":
	case SASLMechanismPlain, SASLMechanismScramSHA256, SASLMechanismScramSHA512:
		if k.SASL.Username == "" || k.SASL.Password == "" {
			return fmt.Errorf("emit.kafka.sasl: username and password are required for %s", k.SASL.Mechanism)
		}
	default:
		return fmt.Errorf("emit.kafka.sasl: unsupported mechanism %q", k.SASL.Mechanism)
	}
	return nil
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
	if pw, ok := os.LookupEnv(KafkaPasswordEnv); ok && pw != "" {
		cfg.Emit.Kafka.SASL.Password = pw
	}
	if err := cfg.Emit.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}
