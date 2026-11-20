package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "parse_dmarc"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	registry *prometheus.Registry

	// Build info
	BuildInfo *prometheus.GaugeVec

	// Report processing metrics
	ReportsFetched      prometheus.Counter
	ReportsParsed       prometheus.Counter
	ReportsStored       prometheus.Counter
	ReportParseErrors   prometheus.Counter
	ReportStoreErrors   prometheus.Counter
	ReportArchiveErrors prometheus.Counter
	AttachmentsTotal    prometheus.Counter
	FetchDuration       prometheus.Histogram
	LastFetchTimestamp  prometheus.Gauge
	FetchCyclesTotal    prometheus.Counter
	FetchErrors         prometheus.Counter

	// IMAP connection metrics
	IMAPConnectionsTotal   *prometheus.CounterVec
	IMAPConnectionDuration prometheus.Histogram

	// Report statistics, from the store at each refresh.
	snapshot *snapshotCollector

	// HTTP server metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight prometheus.Gauge
}

// New creates and registers all Prometheus metrics
func New(version, commit, buildDate string) *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		registry: registry,

		BuildInfo: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "build_info",
				Help:      "Build information for parse-dmarc",
			},
			[]string{"version", "commit", "build_date"},
		),

		// Report processing
		ReportsFetched: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "fetched_total",
				Help:      "Total number of DMARC report emails fetched from IMAP",
			},
		),
		ReportsParsed: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "parsed_total",
				Help:      "Total number of DMARC reports successfully parsed",
			},
		),
		ReportsStored: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "stored_total",
				Help:      "Total number of DMARC reports successfully stored in database",
			},
		),
		ReportParseErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "parse_errors_total",
				Help:      "Total number of DMARC report parse errors",
			},
		),
		ReportStoreErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "store_errors_total",
				Help:      "Total number of DMARC report storage errors",
			},
		),
		ReportArchiveErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "archive_errors_total",
				Help:      "Total number of reports the S3 archive refused; their messages are retried",
			},
		),
		AttachmentsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "attachments_total",
				Help:      "Total number of attachments processed",
			},
		),
		FetchDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "fetch_duration_seconds",
				Help:      "Duration of report fetch operations",
				Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to ~51s
			},
		),
		LastFetchTimestamp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "last_fetch_timestamp_seconds",
				Help:      "Unix timestamp of the last successful fetch operation",
			},
		),
		FetchCyclesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "fetch_cycles_total",
				Help:      "Total number of fetch cycles executed",
			},
		),
		FetchErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "reports",
				Name:      "fetch_errors_total",
				Help:      "Total number of fetch cycle errors",
			},
		),

		// IMAP connection
		IMAPConnectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "imap",
				Name:      "connections_total",
				Help:      "Total number of IMAP connection attempts",
			},
			[]string{"status"}, // "success" or "error"
		),
		IMAPConnectionDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "imap",
				Name:      "connection_duration_seconds",
				Help:      "Duration of IMAP connection establishment",
				Buckets:   prometheus.ExponentialBuckets(0.01, 2, 10), // 10ms to ~5s
			},
		),

		snapshot: newSnapshotCollector(),

		// HTTP server
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "http",
				Name:      "requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "http",
				Name:      "request_duration_seconds",
				Help:      "Duration of HTTP requests",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		HTTPRequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "http",
				Name:      "requests_in_flight",
				Help:      "Number of HTTP requests currently being processed",
			},
		),
	}

	// Register all metrics
	registry.MustRegister(
		// Standard Go collectors
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),

		// Build info
		m.BuildInfo,

		// Report processing
		m.ReportsFetched,
		m.ReportsParsed,
		m.ReportsStored,
		m.ReportParseErrors,
		m.ReportStoreErrors,
		m.ReportArchiveErrors,
		m.AttachmentsTotal,
		m.FetchDuration,
		m.LastFetchTimestamp,
		m.FetchCyclesTotal,
		m.FetchErrors,

		// IMAP
		m.IMAPConnectionsTotal,
		m.IMAPConnectionDuration,

		// Report statistics
		m.snapshot,

		// HTTP
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.HTTPRequestsInFlight,
	)

	// Set build info
	m.BuildInfo.WithLabelValues(version, commit, buildDate).Set(1)

	return m
}

// Handler returns the Prometheus HTTP handler
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// The recording methods below are safe on a nil *Metrics, which is what
// the fetch loop holds when metrics are off.

// FetchCycle counts the start of a fetch cycle.
func (m *Metrics) FetchCycle() {
	if m == nil {
		return
	}
	m.FetchCyclesTotal.Inc()
}

// FetchFailed counts a fetch cycle that ended in an error.
func (m *Metrics) FetchFailed() {
	if m == nil {
		return
	}
	m.FetchErrors.Inc()
}

// FetchSucceeded records a fetch cycle that completed.
func (m *Metrics) FetchSucceeded(duration time.Duration) {
	if m == nil {
		return
	}
	m.FetchDuration.Observe(duration.Seconds())
	m.LastFetchTimestamp.SetToCurrentTime()
}

// MessageFetched counts a report mail handed to the pipeline.
func (m *Metrics) MessageFetched() {
	if m == nil {
		return
	}
	m.ReportsFetched.Inc()
}

// AttachmentSeen counts a report attachment.
func (m *Metrics) AttachmentSeen() {
	if m == nil {
		return
	}
	m.AttachmentsTotal.Inc()
}

// ReportParsed counts a report that parsed.
func (m *Metrics) ReportParsed() {
	if m == nil {
		return
	}
	m.ReportsParsed.Inc()
}

// ReportParseFailed counts a report that did not parse.
func (m *Metrics) ReportParseFailed() {
	if m == nil {
		return
	}
	m.ReportParseErrors.Inc()
}

// ReportStored counts a report saved for the first time.
func (m *Metrics) ReportStored() {
	if m == nil {
		return
	}
	m.ReportsStored.Inc()
}

// ReportStoreFailed counts a report the store refused.
func (m *Metrics) ReportStoreFailed() {
	if m == nil {
		return
	}
	m.ReportStoreErrors.Inc()
}

// ReportArchiveFailed counts a report the archive refused.
func (m *Metrics) ReportArchiveFailed() {
	if m == nil {
		return
	}
	m.ReportArchiveErrors.Inc()
}

// RecordFetchDuration records the duration of a fetch operation
func (m *Metrics) RecordFetchDuration(duration time.Duration) {
	if m == nil {
		return
	}
	m.FetchDuration.Observe(duration.Seconds())
}

// RecordIMAPConnection records an IMAP connection attempt
func (m *Metrics) RecordIMAPConnection(success bool, duration time.Duration) {
	if m == nil {
		return
	}
	status := "success"
	if !success {
		status = "error"
	}
	m.IMAPConnectionsTotal.WithLabelValues(status).Inc()
	m.IMAPConnectionDuration.Observe(duration.Seconds())
}

// SetSnapshot replaces the report statistics the metrics endpoint serves.
func (m *Metrics) SetSnapshot(snap Snapshot) {
	if m == nil {
		return
	}
	m.snapshot.set(snap)
}

// HTTPMiddleware wraps an HTTP handler with metrics instrumentation
func (m *Metrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip metrics endpoint to avoid recursion
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		m.HTTPRequestsInFlight.Inc()
		defer m.HTTPRequestsInFlight.Dec()

		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		path := normalizePath(r.URL.Path)

		m.HTTPRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(wrapped.statusCode)).Inc()
		m.HTTPRequestDuration.WithLabelValues(r.Method, path).Observe(duration.Seconds())
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// normalizePath normalizes URL paths to prevent high cardinality
func normalizePath(path string) string {
	// Normalize common API paths
	switch {
	case path == "/":
		return "/"
	case path == "/api/statistics":
		return "/api/statistics"
	case path == "/api/reports":
		return "/api/reports"
	case path == "/api/top-sources":
		return "/api/top-sources"
	case len(path) > 13 && path[:13] == "/api/reports/":
		return "/api/reports/:id"
	case path == "/api/tlsrpt/statistics", path == "/api/tlsrpt/reports":
		return path
	case len(path) > 20 && path[:20] == "/api/tlsrpt/reports/":
		return "/api/tlsrpt/reports/:id"
	case path == "/metrics", path == "/healthz", path == "/readyz":
		return path
	default:
		// Group static assets
		if len(path) >= 7 && path[:7] == "/assets" {
			return "/assets/*"
		}
		return "/other"
	}
}
