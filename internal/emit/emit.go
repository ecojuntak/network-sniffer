// Package emit writes ServiceCall records as structured JSON records to one or
// more sinks (stdout log lines, Kafka). The field names are the contract the
// dependency-map consumers rely on, so they are defined as constants and
// covered by tests.
package emit

import (
	"bytes"
	"io"
	"log/slog"

	"github.com/ecojuntak/network-sniffer/internal/model"
)

// Log field names. These form the stable output contract.
const (
	FieldSourceWorkload  = "source_workload"
	FieldSourceNamespace = "source_namespace"
	FieldDestWorkload    = "dest_workload"
	FieldDestNamespace   = "dest_namespace"
	FieldDestPort        = "dest_port"
	FieldDestProtocol    = "dest_protocol"
	FieldDestAppProtocol = "dest_app_protocol"
)

// Message is the constant log message under which every edge is recorded.
const Message = "service_call"

// Sink receives every emitted service-call edge. Implementations must be safe
// for concurrent use and must not block for long: Emit runs on the gRPC
// request path.
type Sink interface {
	Emit(model.ServiceCall)
}

// Logger renders ServiceCall records to a structured handler.
type Logger struct {
	log *slog.Logger
}

// New returns a Logger writing JSON lines to w.
func New(w io.Writer) *Logger {
	return NewWithHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// NewWithHandler returns a Logger using a caller-supplied slog handler, for
// callers that want a different format or destination.
func NewWithHandler(h slog.Handler) *Logger {
	return &Logger{log: slog.New(h)}
}

// Emit implements Sink.
func (l *Logger) Emit(sc model.ServiceCall) { l.Log(sc) }

// Log records one service-call edge.
func (l *Logger) Log(sc model.ServiceCall) {
	l.log.Info(Message, attrs(sc)...)
}

// Encode renders sc exactly as Logger writes it (one JSON object, without the
// trailing newline), so every sink shares the same record contract.
func Encode(sc model.ServiceCall) []byte {
	var buf bytes.Buffer
	New(&buf).Log(sc)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func attrs(sc model.ServiceCall) []any {
	return []any{
		slog.String(FieldSourceWorkload, sc.Source.Name),
		slog.String(FieldSourceNamespace, sc.Source.Namespace),
		slog.String(FieldDestWorkload, sc.Dest.Name),
		slog.String(FieldDestNamespace, sc.Dest.Namespace),
		slog.Int(FieldDestPort, int(sc.DestPort)),
		slog.String(FieldDestProtocol, sc.DestProtocol.String()),
		slog.String(FieldDestAppProtocol, appProtocol(sc)),
	}
}

// appProtocol returns the resolved L7 protocol, falling back to the L4 name
// when no application protocol was resolved, so the field is never empty.
func appProtocol(sc model.ServiceCall) string {
	if sc.DestAppProtocol != "" {
		return sc.DestAppProtocol
	}
	return sc.DestProtocol.String()
}
