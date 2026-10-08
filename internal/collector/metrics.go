package collector

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the collector's Prometheus instruments.
type Metrics struct {
	Events         *prometheus.CounterVec
	RecordsSent    prometheus.Counter
	RecordsDropped prometheus.Counter
	ReportErrors   prometheus.Counter
	QueueDepth     prometheus.Gauge
}

// Event results counted by Metrics.Events.
const (
	resultAccepted    = "accepted"
	resultFiltered    = "filtered"
	resultDecodeError = "decode_error"
	resultReadError   = "read_error"
)

// NewMetrics creates the collector metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sniffer_collector_events_total",
			Help: "Connection events read from the eBPF ring buffer, by result.",
		}, []string{"result"}),
		RecordsSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sniffer_collector_records_sent_total",
			Help: "Flow records delivered to the processor.",
		}),
		RecordsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sniffer_collector_records_dropped_total",
			Help: "Flow records dropped because the send queue was full.",
		}),
		ReportErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sniffer_collector_report_errors_total",
			Help: "Failed Report calls to the processor (each is retried).",
		}),
		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sniffer_collector_queue_batches",
			Help: "Batches waiting to be sent to the processor.",
		}),
	}
	reg.MustRegister(m.Events, m.RecordsSent, m.RecordsDropped, m.ReportErrors, m.QueueDepth)
	return m
}
