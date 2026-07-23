package server

import (
	"github.com/kuveris/ocsp/internal/responder"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all registered Prometheus metrics for the OCSP responder.
type Metrics struct {
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	CacheEntries    prometheus.Gauge
	CacheHits       prometheus.Counter
	CacheMisses     prometheus.Counter
	SignerDaysLeft  prometheus.Gauge
	SourceRequests  *prometheus.CounterVec
	SourceLatency   *prometheus.HistogramVec
	SourceRetries   *prometheus.CounterVec
	SourceErrors    *prometheus.CounterVec
}

// Ensure Metrics implements the MetricsRecorder interface.
var _ responder.MetricsRecorder = (*Metrics)(nil)

// RecordRequest records an OCSP request with its method, status, and duration.
func (m *Metrics) RecordRequest(method, status string, durationSeconds float64) {
	m.RequestsTotal.WithLabelValues(method, status).Inc()
	m.RequestDuration.WithLabelValues(method).Observe(durationSeconds)
}

// RecordSourceRequest records a request to the certificate status source.
func (m *Metrics) RecordSourceRequest(sourceName, result string) {
	m.SourceRequests.WithLabelValues(sourceName, result).Inc()
}

func (m *Metrics) RecordSourceLatency(sourceName string, durationSeconds float64) {
	m.SourceLatency.WithLabelValues(sourceName).Observe(durationSeconds)
}

func (m *Metrics) RecordSourceRetry(sourceName string) {
	m.SourceRetries.WithLabelValues(sourceName).Inc()
}

func (m *Metrics) RecordSourceError(sourceName, class string) {
	m.SourceErrors.WithLabelValues(sourceName, class).Inc()
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// NewMetrics registers and returns all Prometheus metrics.
// NewMetrics builds the collector set and the registry that owns it.
//
// The registry is per-instance rather than prometheus.DefaultRegisterer: the
// global one made a second call panic with a duplicate-registration error,
// which blocked `go test -count>1` on this package entirely and meant the
// responder could not be constructed twice in one process.
//
// Moving off the default registry loses the go_* and process_* collectors it
// provides for free, so they are registered explicitly — dropping runtime and
// process telemetry from a long-running service would be a real regression,
// and a silent one.
func NewMetrics() (*Metrics, *prometheus.Registry) {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ocsp_requests_total",
			Help: "Total number of OCSP requests processed.",
		}, []string{"method", "status"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ocsp_request_duration_seconds",
			Help:    "Duration of OCSP request processing in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method"}),

		CacheEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ocsp_cache_entries",
			Help: "Current number of entries in the OCSP response cache.",
		}),

		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ocsp_cache_hits_total",
			Help: "Total number of OCSP cache hits.",
		}),

		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ocsp_cache_misses_total",
			Help: "Total number of OCSP cache misses.",
		}),

		SignerDaysLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ocsp_signer_days_until_expiry",
			Help: "Number of days until the OCSP signing certificate expires.",
		}),

		SourceRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ocsp_source_requests_total",
			Help: "Total number of requests made to the certificate status source.",
		}, []string{"source", "result"}),
		SourceLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ocsp_source_request_duration_seconds",
			Help:    "Latency of certificate status source requests in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"source"}),
		SourceRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ocsp_source_retries_total",
			Help: "Total number of retries performed for source requests.",
		}, []string{"source"}),
		SourceErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ocsp_source_errors_total",
			Help: "Total number of source request errors by class.",
		}, []string{"source", "class"}),
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.CacheEntries,
		m.CacheHits,
		m.CacheMisses,
		m.SignerDaysLeft,
		m.SourceRequests,
		m.SourceLatency,
		m.SourceRetries,
		m.SourceErrors,
	)

	return m, reg
}
