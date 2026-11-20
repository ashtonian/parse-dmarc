package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/api"
	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/imap"
	"github.com/dmarcguardhq/parse-dmarc/internal/ingest"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/jmapintake"
	"github.com/dmarcguardhq/parse-dmarc/internal/logger"
	"github.com/dmarcguardhq/parse-dmarc/internal/maildir"
	"github.com/dmarcguardhq/parse-dmarc/internal/metrics"
	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

func run(ctx context.Context, version, commit, date string) error {
	if genConfig {
		if err := config.GenerateSample(configPath); err != nil {
			return fmt.Errorf("failed to generate config: %w", err)
		}
		log.Info().Str("path", configPath).Msg("sample configuration written")
		return nil
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Reinitialize logger with config-derived level
	log = logger.NewLogger(cfg.LogLevel, !cfg.ColoredLogs)

	// Validate required IMAP configuration when fetching is enabled
	// (not serve-only and not MCP mode)
	if !serveOnly && !mcpMode && mcpHTTPAddr == "" {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}
	}

	if cfg.Database.URL == "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Database.Path), 0o755); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
	}

	store, err := storage.Open(ctx, storage.Options{
		URL:             cfg.Database.URL,
		Path:            cfg.Database.Path,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		ConnMaxLifetime: time.Duration(cfg.Database.ConnMaxLifetimeSeconds) * time.Second,
		ConnMaxIdleTime: time.Duration(cfg.Database.ConnMaxIdleSeconds) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() { _ = store.Close() }()
	log.Info().Str("database", store.Dialect()).Msg("storage ready")

	// Handle MCP mode
	if mcpMode || mcpHTTPAddr != "" {
		return runMCPServer(ctx, store, version)
	}

	// Initialize metrics if enabled
	var m *metrics.Metrics
	if metricsEnabled {
		m = metrics.New(version, commit, date)
		log.Info().Msg("prometheus metrics enabled at /metrics")
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := api.NewServer(store, cfg.Server.Host, cfg.Server.Port, m, log, api.VersionInfo{Version: version, Commit: commit, Date: date})
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start(ctx)
	}()

	// Refresh metrics on startup
	server.RefreshMetrics(ctx)

	if serveOnly {
		log.Info().Msg("running in serve-only mode")
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down")
		case err := <-serverErrChan:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
		}
		return nil
	}

	source, err := newSource(cfg, store, m)
	if err != nil {
		return fmt.Errorf("configure mail source: %w", err)
	}
	pipeline := ingest.New(store, m, log)

	if fetchOnce {
		if err := fetchReports(ctx, source, pipeline, m); err != nil {
			return fmt.Errorf("failed to fetch reports: %w", err)
		}
		server.RefreshMetrics(ctx)
		log.Info().Msg("fetch complete")
		return nil
	}

	log.Info().Int("interval_seconds", fetchInterval).Msg("starting continuous fetch mode")

	if err := fetchReports(ctx, source, pipeline, m); err != nil {
		log.Error().Err(err).Msg("initial fetch failed")
	}
	server.RefreshMetrics(ctx)

	ticker := time.NewTicker(time.Duration(fetchInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := fetchReports(ctx, source, pipeline, m); err != nil {
				log.Error().Err(err).Msg("fetch failed")
			}
			server.RefreshMetrics(ctx)
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return nil
		case err := <-serverErrChan:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
		}
	}
}

// newSource builds the mail source the configuration names: a Maildir when
// MAILDIR_PATH is set, JMAP when JMAP_SESSION_URL is, IMAP otherwise. The
// ledger keeps the progress of a read-only mailbox.
func newSource(cfg *config.Config, ledger intake.Ledger, m *metrics.Metrics) (intake.Source, error) {
	if cfg.Maildir.Path != "" {
		return maildir.NewClient(&cfg.Maildir, log)
	}
	if cfg.JMAP.SessionURL != "" {
		return jmapintake.New(&cfg.JMAP, ledger, log)
	}
	return imap.NewClient(&cfg.IMAP, log, imap.WithConnectionRecorder(m), imap.WithLedger(ledger))
}

// fetchReports runs one fetch cycle: the source hands each new message to
// the pipeline and settles it by the outcome.
func fetchReports(ctx context.Context, source intake.Source, pipeline *ingest.Pipeline, m *metrics.Metrics) error {
	log.Info().Str("source", source.Name()).Msg("fetching reports")
	start := time.Now()
	m.FetchCycle()
	if err := source.Cycle(ctx, pipeline.Handle); err != nil {
		m.FetchFailed()
		return fmt.Errorf("%s: %w", source.Name(), err)
	}
	m.FetchSucceeded(time.Since(start))
	log.Info().Str("source", source.Name()).Dur("duration", time.Since(start)).Msg("fetch complete")
	return nil
}
