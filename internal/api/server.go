package api

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/metrics"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

//go:embed dist
var distFS embed.FS

// VersionInfo is the build the server runs, as main's ldflags set it.
type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Server represents the API server
type Server struct {
	storage         *storage.Storage
	metrics         *metrics.Metrics
	log             *zerolog.Logger
	addr            string
	version         VersionInfo
	shutdownTimeout time.Duration
	cors            corsPolicy
}

// DefaultShutdownTimeout bounds how long in-flight requests may finish once
// the server is asked to stop.
const DefaultShutdownTimeout = 10 * time.Second

// Option configures a Server.
type Option func(*Server)

// WithShutdownTimeout bounds how long in-flight requests may finish on
// shutdown before their connections are closed.
func WithShutdownTimeout(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.shutdownTimeout = d
		}
	}
}

// WithCORSAllowedOrigins lets the listed origins (comma-separated, or "*")
// read the API from another origin, as a dashboard pointed at a remote API
// endpoint does. Without it the API sends no CORS headers.
func WithCORSAllowedOrigins(list string) Option {
	return func(s *Server) { s.cors = parseCORSOrigins(list) }
}

// NewServer creates a new API server
func NewServer(store *storage.Storage, host string, port int, m *metrics.Metrics, log *zerolog.Logger, version VersionInfo, opts ...Option) *Server {
	s := &Server{
		storage:         store,
		metrics:         m,
		log:             log,
		addr:            fmt.Sprintf("%s:%d", host, port),
		version:         version,
		shutdownTimeout: DefaultShutdownTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/reports", s.handleReports)
	mux.HandleFunc("/api/reports/", s.handleReportDetail)
	mux.HandleFunc("/api/statistics", s.handleStatistics)
	mux.HandleFunc("/api/top-sources", s.handleTopSources)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/api/tlsrpt/statistics", s.handleTLSStatistics)
	mux.HandleFunc("/api/tlsrpt/reports", s.handleTLSReports)
	mux.HandleFunc("/api/tlsrpt/reports/", s.handleTLSReportDetail)

	// Prometheus metrics endpoint
	if s.metrics != nil {
		mux.Handle("/metrics", s.metrics.Handler())
	}

	// Serve frontend
	// Try to serve embedded files, fallback to nothing if not embedded
	distFiles, err := fs.Sub(distFS, "dist")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(distFiles)))
	} else {
		// If dist folder is not embedded, serve a simple message
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html")
				_, _ = fmt.Fprintf(w, `
					<!DOCTYPE html>
					<html>
					<head><title>DMARC Dashboard</title></head>
					<body>
						<h1>DMARC Report Dashboard API</h1>
						<p>API is running. Frontend assets not embedded yet.</p>
						<ul>
							<li><a href="/api/statistics">Statistics</a></li>
							<li><a href="/api/reports">Reports</a></li>
							<li><a href="/api/top-sources">Top Sources</a></li>
							<li><a href="/metrics">Prometheus Metrics</a></li>
						</ul>
					</body>
					</html>
				`)
			} else {
				http.NotFound(w, r)
			}
		})
	}

	// Build handler chain: CORS -> Metrics -> Routes
	var handler http.Handler = mux
	if s.metrics != nil {
		handler = s.metrics.HTTPMiddleware(handler)
	}
	handler = s.corsMiddleware(handler)

	server := newHTTPServer(s.addr, handler)

	s.log.Info().Str("addr", s.addr).Msg("starting server")
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServe() }()

	select {
	case err := <-served:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server listen on %s: %w", s.addr, err)
		}
		return nil
	case <-ctx.Done():
	}

	// Start returns only once in-flight requests are done, so the caller
	// can close the store behind them.
	s.log.Info().Dur("timeout", s.shutdownTimeout).Msg("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("HTTP server shutdown: %w", err)
	}
	return nil
}

// Timeouts of the dashboard HTTP server. They mirror the ones the MCP server
// sets in internal/mcp/server.go, so both operator-facing surfaces bound idle
// and slow clients the same way.
const (
	readTimeout    = 15 * time.Second
	writeTimeout   = 15 * time.Second
	idleTimeout    = 60 * time.Second
	maxHeaderBytes = 1 << 20 // 1 MiB
)

// newHTTPServer builds the dashboard server with the same slow-client bounds
// the MCP server applies.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}
}

// corsMiddleware answers cross-origin requests only from the configured
// origins. The API has no authentication, so a wildcard would let any web
// page a user opens read the reports of a dashboard their browser can
// reach, loopback and LAN included.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !s.cors.allows(origin) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Add("Vary", "Origin")
		if s.cors.any {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsPolicy is the set of origins allowed to read the API cross-origin.
type corsPolicy struct {
	any     bool
	origins map[string]bool
}

// parseCORSOrigins reads a comma-separated origin list; "*" allows any.
func parseCORSOrigins(list string) corsPolicy {
	p := corsPolicy{origins: map[string]bool{}}
	for _, o := range strings.Split(list, ",") {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		switch o {
		case "":
		case "*":
			p.any = true
		default:
			p.origins[strings.ToLower(o)] = true
		}
	}
	return p
}

func (p corsPolicy) allows(origin string) bool {
	return p.any || p.origins[strings.ToLower(origin)]
}

// handleReports returns a list of reports
func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse pagination parameters
	limit := 50
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > storage.MaxReportLimit {
		limit = storage.MaxReportLimit
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	reports, err := s.storage.GetReports(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, reports)
}

// handleReportDetail returns a single report detail
func (s *Server) handleReportDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from URL
	idStr := r.URL.Path[len("/api/reports/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid report ID", http.StatusBadRequest)
		return
	}

	report, err := s.storage.GetReportByID(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.writeJSON(w, report)
}

// handleStatistics returns dashboard statistics
func (s *Server) handleStatistics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.storage.GetStatistics(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, stats)
}

// handleTopSources returns top source IPs
func (s *Server) handleTopSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	sources, err := s.storage.GetTopSourceIPs(r.Context(), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, sources)
}

// handleVersion returns the build the server runs
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeJSON(w, s.version)
}

// writeJSON writes JSON response
func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.log.Error().Err(err).Msg("failed to encode JSON")
	}
}

// RefreshMetrics replaces the report statistics /metrics serves with the
// store's current state. A query that fails keeps the previous statistics
// in place rather than serving a partial set.
func (s *Server) RefreshMetrics(ctx context.Context) {
	if s.metrics == nil {
		return
	}
	snap, err := s.snapshot(ctx)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to refresh report metrics")
		return
	}
	s.metrics.SetSnapshot(snap)
}

func (s *Server) snapshot(ctx context.Context) (metrics.Snapshot, error) {
	var snap metrics.Snapshot

	stats, err := s.storage.GetStatistics(ctx)
	if err != nil {
		return snap, err
	}
	snap.TotalReports = stats.TotalReports
	snap.TotalMessages = stats.TotalMessages
	snap.CompliantMessages = stats.CompliantMessages
	snap.ComplianceRate = stats.ComplianceRate
	snap.UniqueSourceIPs = stats.UniqueSourceIPs
	snap.UniqueDomains = stats.UniqueDomains

	domains, err := s.storage.GetDomainStats(ctx)
	if err != nil {
		return snap, err
	}
	for _, d := range domains {
		snap.Domains = append(snap.Domains, metrics.DomainSnapshot{
			Domain:                  d.Domain,
			Messages:                d.TotalMessages,
			CompliantMessages:       d.CompliantMessages,
			UnalignedMessages:       d.UnalignedMessages,
			UnauthenticatedMessages: d.UnauthenticatedMessages,
			LastReport:              d.LastReport,
			LastUnaligned:           d.LastUnaligned,
			LastUnauthenticated:     d.LastUnauthenticated,
		})
	}

	orgs, err := s.storage.GetOrgStats(ctx)
	if err != nil {
		return snap, err
	}
	snap.Orgs = make(map[string]int, len(orgs))
	for _, o := range orgs {
		snap.Orgs[o.OrgName] += o.Reports
	}

	disp, err := s.storage.GetDispositionStats(ctx)
	if err != nil {
		return snap, err
	}
	snap.Dispositions = make(map[string]int, len(disp))
	for _, d := range disp {
		snap.Dispositions[d.Disposition] += d.Count
	}

	spf, err := s.storage.GetSPFStats(ctx)
	if err != nil {
		return snap, err
	}
	snap.SPFResults = make(map[string]int, len(spf))
	for _, r := range spf {
		snap.SPFResults[r.Result] += r.Count
	}
	dkim, err := s.storage.GetDKIMStats(ctx)
	if err != nil {
		return snap, err
	}
	snap.DKIMResults = make(map[string]int, len(dkim))
	for _, r := range dkim {
		snap.DKIMResults[r.Result] += r.Count
	}

	tls, err := s.storage.GetTLSStatistics(ctx)
	if err != nil {
		return snap, err
	}
	for _, d := range tls.Domains {
		snap.TLSDomains = append(snap.TLSDomains, metrics.TLSDomainSnapshot{
			Domain:      d.PolicyDomain,
			Successful:  d.SuccessfulSessions,
			Failed:      d.FailedSessions,
			LastReport:  d.LastReport,
			LastFailure: d.LastFailure,
		})
	}
	snap.TLSFailureTypes = map[string]int64{}
	for _, f := range tls.FailureTypes {
		snap.TLSFailureTypes[knownTLSResultType(f.ResultType)] += f.FailedSessions
	}
	return snap, nil
}

// knownTLSResultType keeps a result type RFC 8460 defines and folds any
// other, which a reporter or a forged report may send, into "other".
func knownTLSResultType(t string) string {
	if slices.Contains(parser.TLSResultTypes, t) {
		return t
	}
	return metrics.OtherLabel
}

// GetMetrics returns the metrics instance
func (s *Server) GetMetrics() *metrics.Metrics {
	return s.metrics
}
