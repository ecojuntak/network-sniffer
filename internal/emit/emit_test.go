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
