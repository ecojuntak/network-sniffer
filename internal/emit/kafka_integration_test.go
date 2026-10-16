//go:build integration

package emit_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/ecojuntak/network-sniffer/internal/config"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/kafkatest"
	"github.com/ecojuntak/network-sniffer/internal/model"
)

func call(src, dst string, port uint16) model.ServiceCall {
	return model.ServiceCall{
		Source:       model.Workload{Name: src, Namespace: "shop", Kind: "Deployment"},
		Dest:         model.Workload{Name: dst, Namespace: "payments", Kind: "Deployment"},
		DestPort:     port,
		DestProtocol: model.ProtocolTCP,
	}
}

// errRecorder collects error callbacks from the producer goroutines.
type errRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *errRecorder) record(_ string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *errRecorder) get() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func newSink(t *testing.T, cfg config.KafkaConfig, onErr func(string, error)) *emit.Kafka {
	t.Helper()
	k, err := emit.NewKafka(cfg, onErr)
	if err != nil {
		t.Fatalf("NewKafka: %v", err)
	}
	return k
}

func TestIntegrationKafkaPlaintext(t *testing.T) {
	b := kafkatest.Start(t, false)
	const topic = "service-calls"
	b.CreateTopic(t, topic)

	errs := &errRecorder{}
	k := newSink(t, config.KafkaConfig{Brokers: []string{b.Addr}, Topic: topic}, errs.record)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := k.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}

	calls := []model.ServiceCall{call("frontend", "checkout", 8080), call("frontend", "cart", 9090), call("worker", "db", 5432)}
	for _, sc := range calls {
		k.Emit(sc)
	}
	if err := k.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if e := errs.get(); len(e) > 0 {
		t.Fatalf("produce errors: %v", e)
	}

	recs := b.Consume(t, topic, len(calls), 30*time.Second)
	if len(recs) != len(calls) {
		t.Fatalf("consumed %d records, want %d", len(recs), len(calls))
	}
	for i, r := range recs {
		sc := calls[i]
		if want := sc.Source.Namespace + "/" + sc.Source.Name; string(r.Key) != want {
			t.Errorf("record %d key = %q, want %q", i, r.Key, want)
		}
		var rec map[string]any
		if err := json.Unmarshal(r.Value, &rec); err != nil {
			t.Fatalf("record %d not JSON: %v\n%s", i, err, r.Value)
		}
		want := map[string]any{
			"msg":                     emit.Message,
			emit.FieldSourceWorkload:  sc.Source.Name,
			emit.FieldSourceNamespace: sc.Source.Namespace,
			emit.FieldDestWorkload:    sc.Dest.Name,
			emit.FieldDestNamespace:   sc.Dest.Namespace,
			emit.FieldDestPort:        float64(sc.DestPort),
			emit.FieldDestProtocol:    "tcp",
			emit.FieldDestAppProtocol: "tcp",
		}
		for f, v := range want {
			if rec[f] != v {
				t.Errorf("record %d field %q = %v, want %v", i, f, rec[f], v)
			}
		}
	}
}

// A topic that does not exist must fail the startup check rather than drop
// every edge at runtime.
func TestIntegrationKafkaMissingTopic(t *testing.T) {
	b := kafkatest.Start(t, false)
	k := newSink(t, config.KafkaConfig{Brokers: []string{b.Addr}, Topic: "does-not-exist"}, nil)
	defer k.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := k.Check(ctx)
	if err == nil {
		t.Fatal("Check = nil, want unknown topic error")
	}
	t.Logf("Check: %v", err)
}

func TestIntegrationKafkaSASL(t *testing.T) {
	b := kafkatest.Start(t, true)
	const topic = "service-calls-sasl"
	b.CreateTopic(t, topic)

	cfg := config.KafkaConfig{
		Brokers: []string{b.Addr},
		Topic:   topic,
		SASL: config.KafkaSASLConfig{
			Mechanism: config.SASLMechanismScramSHA256,
			Username:  kafkatest.User,
			Password:  kafkatest.Password,
		},
	}

	t.Run("valid credentials", func(t *testing.T) {
		errs := &errRecorder{}
		k := newSink(t, cfg, errs.record)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := k.Check(ctx); err != nil {
			t.Fatalf("Check: %v", err)
		}
		k.Emit(call("frontend", "checkout", 8080))
		if err := k.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if e := errs.get(); len(e) > 0 {
			t.Fatalf("produce errors: %v", e)
		}
		if recs := b.Consume(t, topic, 1, 30*time.Second); len(recs) != 1 {
			t.Fatalf("consumed %d records, want 1", len(recs))
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		bad := cfg
		bad.SASL.Password = "wrong"
		k := newSink(t, bad, nil)
		defer k.Close(context.Background())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := k.Check(ctx)
		if err == nil {
			t.Fatal("Check = nil, want authentication error")
		}
		t.Logf("Check: %v", err)
	})
}
