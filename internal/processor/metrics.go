package processor

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the processor's Prometheus instruments.
type Metrics struct {
	Records    *prometheus.CounterVec
	Batches    prometheus.Counter
	EmitErrors *prometheus.CounterVec
}

// Record results counted by Metrics.Records.
const (
	resultInvalid           = "invalid"
	resultReversedDuplicate = "reversed_duplicate"
	resultIgnored           = "ignored"
	resultDuplicate         = "duplicate"
	resultEmitted           = "emitted"
)

// NewMetrics creates the processor metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Records: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sniffer_processor_records_total",
			Help: "Flow records received from collectors, by pipeline result.",
		}, []string{"result"}),
		Batches: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sniffer_processor_batches_total",
			Help: "Report batches received from collectors.",
		}),
		EmitErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sniffer_processor_emit_errors_total",
			Help: "Edges an output sink failed to deliver, by sink and reason.",
		}, []string{"sink", "reason"}),
	}
	reg.MustRegister(m.Records, m.Batches, m.EmitErrors)
	return m
}
