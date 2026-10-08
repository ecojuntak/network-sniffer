package processor

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the processor's Prometheus instruments.
type Metrics struct {
	Records *prometheus.CounterVec
	Batches prometheus.Counter
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
	}
	reg.MustRegister(m.Records, m.Batches)
	return m
}
