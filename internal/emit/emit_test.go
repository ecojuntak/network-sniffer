package emit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

func TestLogEmitsContractFields(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	l.Log(model.ServiceCall{
		Source:       model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"},
		Dest:         model.Workload{Name: "checkout", Namespace: "payments", Kind: "Rollout"},
		DestPort:     8080,
		DestProtocol: model.ProtocolTCP,
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	want := map[string]any{
		FieldSourceWorkload:  "frontend",
		FieldSourceNamespace: "shop",
		FieldDestWorkload:    "checkout",
		FieldDestNamespace:   "payments",
		FieldDestProtocol:    "tcp",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("field %q = %v, want %v", k, rec[k], v)
		}
	}
	// JSON numbers decode as float64.
	if rec[FieldDestPort] != float64(8080) {
		t.Errorf("field %q = %v, want 8080", FieldDestPort, rec[FieldDestPort])
	}
	if rec["msg"] != Message {
		t.Errorf("msg = %v, want %q", rec["msg"], Message)
	}
}

func TestLogAppProtocol(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log(model.ServiceCall{
		Source:          model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"},
		Dest:            model.Workload{Name: "checkout", Namespace: "shop", Kind: "Rollout"},
		DestPort:        8080,
		DestProtocol:    model.ProtocolTCP,
		DestAppProtocol: "grpc",
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec[FieldDestAppProtocol] != "grpc" {
		t.Errorf("app protocol = %v, want grpc", rec[FieldDestAppProtocol])
	}
	// L4 field stays authoritative and untouched.
	if rec[FieldDestProtocol] != "tcp" {
		t.Errorf("L4 protocol = %v, want tcp", rec[FieldDestProtocol])
	}
}

func TestLogAppProtocolFallsBackToL4(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log(model.ServiceCall{
		Source:       model.Workload{Name: "a", Namespace: "ns", Kind: "Deployment"},
		Dest:         model.Workload{Name: "b", Namespace: "ns", Kind: "Deployment"},
		DestPort:     5432,
		DestProtocol: model.ProtocolTCP,
		// DestAppProtocol unset: field must fall back to the L4 name.
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec[FieldDestAppProtocol] != "tcp" {
		t.Errorf("app protocol = %v, want tcp fallback", rec[FieldDestAppProtocol])
	}
}

func TestLogExternalDestination(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	l.Log(model.ServiceCall{
		Source:       model.Workload{Name: "worker", Namespace: "jobs", Kind: "Deployment"},
		Dest:         model.Workload{Name: "8.8.8.8", Kind: model.KindExternal},
		DestPort:     53,
		DestProtocol: model.ProtocolUDP,
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec[FieldDestWorkload] != "8.8.8.8" {
		t.Errorf("dest workload = %v, want 8.8.8.8", rec[FieldDestWorkload])
	}
	if rec[FieldDestNamespace] != "" {
		t.Errorf("dest namespace = %v, want empty", rec[FieldDestNamespace])
	}
	if rec[FieldDestProtocol] != "udp" {
		t.Errorf("dest protocol = %v, want udp", rec[FieldDestProtocol])
	}
}

func TestLogOneLinePerCall(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	sc := model.ServiceCall{
		Source:       model.Workload{Name: "a", Namespace: "ns", Kind: "Deployment"},
		Dest:         model.Workload{Name: "b", Namespace: "ns", Kind: "Deployment"},
		DestPort:     80,
		DestProtocol: model.ProtocolTCP,
	}
	l.Log(sc)
	l.Log(sc)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2:\n%s", len(lines), buf.String())
	}
}

// Encode must produce the exact object the stdout sink logs, so Kafka and log
// consumers share one contract.
func TestEncodeMatchesLogLine(t *testing.T) {
	sc := model.ServiceCall{
		Source:       model.Workload{Name: "frontend", Namespace: "shop", Kind: "Deployment"},
		Dest:         model.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"},
		DestPort:     8080,
		DestProtocol: model.ProtocolTCP,
	}
	var buf bytes.Buffer
	New(&buf).Emit(sc)

	var logged, encoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatal(err)
	}
	enc := Encode(sc)
	if bytes.HasSuffix(enc, []byte("\n")) {
		t.Errorf("Encode output has trailing newline")
	}
	if err := json.Unmarshal(enc, &encoded); err != nil {
		t.Fatal(err)
	}
	delete(logged, "time")
	delete(encoded, "time")
	if len(logged) != len(encoded) {
		t.Fatalf("logged %v, encoded %v", logged, encoded)
	}
	for k, v := range logged {
		if encoded[k] != v {
			t.Errorf("field %q: encoded %v, logged %v", k, encoded[k], v)
		}
	}
}

type recordSink struct{ got []model.ServiceCall }

func (r *recordSink) Emit(sc model.ServiceCall) { r.got = append(r.got, sc) }

func TestMultiFansOut(t *testing.T) {
	a, b := &recordSink{}, &recordSink{}
	sc := model.ServiceCall{Source: model.Workload{Name: "a"}}
	Multi(a, b).Emit(sc)
	if len(a.got) != 1 || len(b.got) != 1 {
		t.Fatalf("a=%d b=%d, want 1 each", len(a.got), len(b.got))
	}
	if s := Multi(a); s != Sink(a) {
		t.Fatal("Multi(single) should return the sink unchanged")
	}
}
