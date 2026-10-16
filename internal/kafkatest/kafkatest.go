//go:build integration

// Package kafkatest starts a throwaway Kafka-compatible broker (Redpanda) in a
// container for integration tests and provides helpers to create topics and
// read them back. It needs a Docker-compatible container runtime; see the
// test-integration target in the Makefile.
package kafkatest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redpanda"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// DefaultImage is the Redpanda image used for the broker. It is pulled through
// mirror.gcr.io to avoid Docker Hub's anonymous pull rate limit; set
// ImageEnv to use another image or registry.
const DefaultImage = "mirror.gcr.io/redpandadata/redpanda:v23.3.3"

// ImageEnv overrides DefaultImage.
const ImageEnv = "KAFKATEST_IMAGE"

// Superuser credentials of a SASL-enabled broker (SCRAM-SHA-256).
const (
	User     = "sniffer"
	Password = "sniffer-secret"
)

// Broker is a running broker.
type Broker struct {
	// Addr is the seed broker address reachable from the test.
	Addr string
	sasl bool
}

// Start runs a broker for the duration of the test. With sasl, the Kafka API
// requires SCRAM-SHA-256 authentication as User/Password.
func Start(t *testing.T, sasl bool) *Broker {
	t.Helper()
	ctx := context.Background()
	var opts []testcontainers.ContainerCustomizer
	if sasl {
		opts = append(opts,
			redpanda.WithEnableSASL(),
			redpanda.WithNewServiceAccount(User, Password),
			redpanda.WithSuperusers(User),
		)
	}
	img := DefaultImage
	if v := os.Getenv(ImageEnv); v != "" {
		img = v
	}
	c, err := redpanda.Run(ctx, img, opts...)
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("start redpanda: %v", err)
	}
	addr, err := c.KafkaSeedBroker(ctx)
	if err != nil {
		t.Fatalf("seed broker: %v", err)
	}
	return &Broker{Addr: addr, sasl: sasl}
}

// Client returns an admin/consumer client authenticated as the superuser when
// SASL is enabled. Extra options are appended.
func (b *Broker) Client(t *testing.T, opts ...kgo.Opt) *kgo.Client {
	t.Helper()
	base := []kgo.Opt{kgo.SeedBrokers(b.Addr)}
	if b.sasl {
		base = append(base, kgo.SASL(scram.Auth{User: User, Pass: Password}.AsSha256Mechanism()))
	}
	cl, err := kgo.NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatalf("kafka client: %v", err)
	}
	t.Cleanup(cl.Close)
	return cl
}

// CreateTopic creates a single-partition topic.
func (b *Broker) CreateTopic(t *testing.T, topic string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := kmsg.NewPtrCreateTopicsRequest()
	rt := kmsg.NewCreateTopicsRequestTopic()
	rt.Topic = topic
	rt.NumPartitions = 1
	rt.ReplicationFactor = 1
	req.Topics = append(req.Topics, rt)
	resp, err := req.RequestWith(ctx, b.Client(t))
	if err != nil {
		t.Fatalf("create topic %q: %v", topic, err)
	}
	if err := kerr.ErrorForCode(resp.Topics[0].ErrorCode); err != nil {
		t.Fatalf("create topic %q: %v", topic, err)
	}
}

// Consume reads records from the start of topic until want records arrived or
// the timeout elapsed, and returns what it read.
func (b *Broker) Consume(t *testing.T, topic string, want int, timeout time.Duration) []*kgo.Record {
	t.Helper()
	cl := b.Client(t, kgo.ConsumeTopics(topic), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var got []*kgo.Record
	for len(got) < want {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			break
		}
		for _, fe := range fs.Errors() {
			t.Fatalf("fetch %s/%d: %v", fe.Topic, fe.Partition, fe.Err)
		}
		got = append(got, fs.Records()...)
	}
	return got
}
