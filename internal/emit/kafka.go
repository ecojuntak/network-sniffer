package emit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/ecojuntak/network-sniffer/internal/config"
	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Reasons passed to the Kafka error callback.
const (
	// ReasonBufferFull: the producer buffer was full and the edge was dropped
	// rather than blocking the gRPC request path.
	ReasonBufferFull = "buffer_full"
	// ReasonProduce: the broker did not accept the record.
	ReasonProduce = "produce"
)

// kafkaMaxBuffered bounds the records held in memory while brokers are slow or
// unreachable; beyond it edges are dropped and reported.
const kafkaMaxBuffered = 10000

// Kafka produces each edge as one JSON record (the same object the stdout sink
// logs) keyed by "<source_namespace>/<source_workload>", so a caller's edges
// stay ordered within one partition.
type Kafka struct {
	cl    *kgo.Client
	topic string
	onErr func(reason string, err error)
}

// NewKafka builds a Kafka sink from cfg. onErr, if non-nil, is called for each
// dropped or failed record; it runs on producer goroutines and must be cheap
// and concurrency-safe. Call Check to verify connectivity and Close to flush.
func NewKafka(cfg config.KafkaConfig, onErr func(reason string, err error)) (*Kafka, error) {
	if onErr == nil {
		onErr = func(string, error) {}
	}
	clientID := cfg.ClientID
	if clientID == "" {
		clientID = config.DefaultKafkaClientID
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.ClientID(clientID),
		kgo.MaxBufferedRecords(kafkaMaxBuffered),
		kgo.ProducerLinger(50 * time.Millisecond),
	}
	if cfg.TLS.Enabled {
		tc, err := tlsConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.DialTLSConfig(tc))
	}
	if cfg.SASL.Mechanism != "" {
		m, err := saslMechanism(cfg.SASL)
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.SASL(m))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("kafka client: %w", err)
	}
	return &Kafka{cl: cl, topic: cfg.Topic, onErr: onErr}, nil
}

// Check verifies the brokers are reachable, authentication succeeds and the
// topic exists, so a misconfigured sink fails at startup rather than silently
// dropping every edge.
func (k *Kafka) Check(ctx context.Context) error {
	req := kmsg.NewPtrMetadataRequest()
	t := kmsg.NewMetadataRequestTopic()
	t.Topic = kmsg.StringPtr(k.topic)
	req.Topics = append(req.Topics, t)
	resp, err := req.RequestWith(ctx, k.cl)
	if err != nil {
		return fmt.Errorf("kafka metadata: %w", err)
	}
	if len(resp.Topics) != 1 {
		return fmt.Errorf("kafka metadata: got %d topics, want 1", len(resp.Topics))
	}
	if err := kerr.ErrorForCode(resp.Topics[0].ErrorCode); err != nil {
		return fmt.Errorf("kafka topic %q: %w", k.topic, err)
	}
	return nil
}

// Emit implements Sink. It never blocks: when the producer buffer is full the
// edge is dropped and reported via the error callback.
func (k *Kafka) Emit(sc model.ServiceCall) {
	rec := &kgo.Record{
		Key:   []byte(sc.Source.Namespace + "/" + sc.Source.Name),
		Value: Encode(sc),
	}
	k.cl.TryProduce(context.Background(), rec, func(_ *kgo.Record, err error) {
		switch {
		case err == nil:
		case errors.Is(err, kgo.ErrMaxBuffered):
			k.onErr(ReasonBufferFull, err)
		default:
			k.onErr(ReasonProduce, err)
		}
	})
}

// Close flushes buffered records (bounded by ctx) and closes the client.
func (k *Kafka) Close(ctx context.Context) error {
	err := k.cl.Flush(ctx)
	k.cl.Close()
	return err
}

func tlsConfig(c config.KafkaTLSConfig) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kafka tls ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kafka tls ca %q: no certificates found", c.CAFile)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

func saslMechanism(c config.KafkaSASLConfig) (sasl.Mechanism, error) {
	switch c.Mechanism {
	case config.SASLMechanismPlain:
		return plain.Auth{User: c.Username, Pass: c.Password}.AsMechanism(), nil
	case config.SASLMechanismScramSHA256:
		return scram.Auth{User: c.Username, Pass: c.Password}.AsSha256Mechanism(), nil
	case config.SASLMechanismScramSHA512:
		return scram.Auth{User: c.Username, Pass: c.Password}.AsSha512Mechanism(), nil
	default:
		return nil, fmt.Errorf("unsupported sasl mechanism %q", c.Mechanism)
	}
}
