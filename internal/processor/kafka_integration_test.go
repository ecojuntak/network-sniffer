//go:build integration

package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ecojuntak/network-sniffer/internal/config"
	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/ignore"
	"github.com/ecojuntak/network-sniffer/internal/kafkatest"
	"github.com/ecojuntak/network-sniffer/internal/model"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// Edges reported by collectors reach Kafka and stdout through the full
// pipeline; filtered and duplicate records reach neither.
func TestIntegrationPipelineEmitsToKafka(t *testing.T) {
	b := kafkatest.Start(t, false)
	const topic = "pipeline-edges"
	b.CreateTopic(t, topic)

	cache := resolver.NewCache()
	cache.Upsert(frontendIP, frontend)
	cache.Upsert(checkoutIP, checkout)
	cache.Upsert(nodeIP, model.Workload{Name: "ip-100-90-106-4", Kind: model.KindNode})
	matcher, err := ignore.Compile([]string{"/ip-*"})
	if err != nil {
		t.Fatal(err)
	}

	k, err := emit.NewKafka(config.KafkaConfig{Brokers: []string{b.Addr}, Topic: topic}, func(reason string, err error) {
		t.Errorf("kafka emit error (%s): %v", reason, err)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := k.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}

	var out bytes.Buffer
	m := NewMetrics(prometheus.NewRegistry())
	p := NewPipeline(cache, matcher, dedup.New(time.Minute), emit.Multi(emit.New(&out), k), m)
	f := fixture{srv: NewServer(p, m), m: m, out: &out}

	report(t, f,
		record(frontendIP, checkoutIP, 8080, true, ""), // emitted
		record(frontendIP, checkoutIP, 8080, true, ""), // duplicate
		record(nodeIP, checkoutIP, 15021, true, ""),    // ignored (node probe)
		record(checkoutIP, frontendIP, 9090, true, ""), // emitted
	)
	if err := k.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := []string{"frontend -> checkout:8080", "checkout -> frontend:9090"}
	if got := edges(t, &out); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("stdout edges = %v, want %v", got, want)
	}

	// Ask for one more than expected so extra (unfiltered) records would show.
	recs := b.Consume(t, topic, len(want)+1, 10*time.Second)
	var got []string
	for _, r := range recs {
		var rec map[string]any
		if err := json.Unmarshal(r.Value, &rec); err != nil {
			t.Fatalf("bad JSON record %q: %v", r.Value, err)
		}
		got = append(got, fmt.Sprintf("%s -> %s:%v",
			rec[emit.FieldSourceWorkload], rec[emit.FieldDestWorkload], rec[emit.FieldDestPort]))
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("kafka edges = %v, want %v", got, want)
	}
}
