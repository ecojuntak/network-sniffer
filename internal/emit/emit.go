// Package emit writes ServiceCall records as structured JSON log lines. The
// field names are the contract the dependency-map consumers rely on, so they
// are defined as constants and covered by tests.
package emit

import (
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
)

// Message is the constant log message under which every edge is recorded.
const Message = "service_call"

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

// Log records one service-call edge.
func (l *Logger) Log(sc model.ServiceCall) {
	l.log.Info(Message,
		slog.String(FieldSourceWorkload, sc.Source.Name),
		slog.String(FieldSourceNamespace, sc.Source.Namespace),
		slog.String(FieldDestWorkload, sc.Dest.Name),
		slog.String(FieldDestNamespace, sc.Dest.Namespace),
		slog.Int(FieldDestPort, int(sc.DestPort)),
		slog.String(FieldDestProtocol, sc.DestProtocol.String()),
	)
}
