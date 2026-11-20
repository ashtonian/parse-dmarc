package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/api"
	"github.com/dmarcguardhq/parse-dmarc/internal/archive"
	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
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

	// Reinitialize logger with config-derived level and format
	log, err = logger.New(cfg.LogLevel, cfg.LogFormat, !cfg.ColoredLogs)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

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

	server := api.NewServer(store, cfg.Server.Host, cfg.Server.Port, m, log,
		api.VersionInfo{Version: version, Commit: commit, Date: date},
		api.WithShutdownTimeout(time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second),
		api.WithCORSAllowedOrigins(cfg.Server.CORSAllowedOrigins))
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start(ctx)
	}()
	// The store closes after the server has drained: wait for Start on
	// every way out once it is running.
	serverDone := false
	defer func() {
		stop()
		if !serverDone {
			if err := <-serverErrChan; err != nil {
				log.Error().Err(err).Msg("server shutdown")
			}
		}
	}()

	// Refresh metrics on startup
	server.RefreshMetrics(ctx)

	if serveOnly {
		log.Info().Msg("running in serve-only mode")
		select {
		case <-ctx.Done():
			log.Info().Msg("shutting down")
		case err := <-serverErrChan:
			serverDone = true
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
	var pipelineOpts []ingest.Option
	if cfg.Enrich.Enabled() {
		enricher, err := newEnricher(cfg.Enrich)
		if err != nil {
			return fmt.Errorf("configure enrichment: %w", err)
		}
		defer func() { _ = enricher.Close() }()
		pipelineOpts = append(pipelineOpts, ingest.WithEnricher(enricher, store,
			time.Duration(cfg.Enrich.RefreshDays)*24*time.Hour))
		log.Info().
			Bool("reverse_dns", cfg.Enrich.ReverseDNS).
			Bool("service_map", cfg.Enrich.ServiceMap != "").
			Int("ip_databases", len(cfg.Enrich.IPDatabases)).
			Msg("source enrichment enabled")
	}
	if cfg.Archive.Bucket != "" {
		arch, err := archive.New(ctx, archive.Config{
			Endpoint:        cfg.Archive.Endpoint,
			Bucket:          cfg.Archive.Bucket,
			Region:          cfg.Archive.Region,
			AccessKeyID:     cfg.Archive.AccessKeyID,
			SecretAccessKey: cfg.Archive.SecretAccessKey,
			SessionToken:    cfg.Archive.SessionToken,
			Prefix:          cfg.Archive.Prefix,
			PathStyle:       archive.PathStyle(cfg.Archive.PathStyle),
			CAFile:          cfg.Archive.CAFile,
			Timeout:         time.Duration(cfg.Archive.TimeoutSeconds) * time.Second,
		})
		if err != nil {
			return fmt.Errorf("configure S3 archive: %w", err)
		}
		pipelineOpts = append(pipelineOpts, ingest.WithArchive(arch))
		log.Info().Str("bucket", cfg.Archive.Bucket).Str("prefix", cfg.Archive.Prefix).Msg("S3 archive enabled")
	}
	pipeline := ingest.New(store, m, log, pipelineOpts...)
	fetchTimeout := time.Duration(cfg.FetchTimeoutSeconds) * time.Second
	retention := time.Duration(cfg.RetentionDays) * 24 * time.Hour
	cycle := func() error {
		err := fetchReports(ctx, source, pipeline, m, fetchTimeout)
		prune(ctx, store, retention)
		server.RefreshMetrics(ctx)
		return err
	}

	if fetchOnce {
		if err := cycle(); err != nil {
			return fmt.Errorf("failed to fetch reports: %w", err)
		}
		log.Info().Msg("fetch complete")
		return nil
	}

	log.Info().Int("interval_seconds", fetchInterval).Msg("starting continuous fetch mode")

	if err := cycle(); err != nil {
		log.Error().Err(err).Msg("initial fetch failed")
	}

	ticker := time.NewTicker(time.Duration(fetchInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := cycle(); err != nil {
				log.Error().Err(err).Msg("fetch failed")
			}
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return nil
		case err := <-serverErrChan:
			serverDone = true
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		}
	}
}

// prune deletes the reports older than retention, when one is set.
func prune(ctx context.Context, store *storage.Storage, retention time.Duration) {
	if retention <= 0 || ctx.Err() != nil {
		return
	}
	p, err := store.PruneBefore(ctx, time.Now().Add(-retention))
	if err != nil {
		log.Error().Err(err).Msg("pruning old reports")
		return
	}
	if p.DMARCReports+p.TLSRPTReports > 0 {
		log.Info().
			Int64("dmarc_reports", p.DMARCReports).
			Int64("tlsrpt_reports", p.TLSRPTReports).
			Int64("sources", p.Sources).
			Msg("pruned reports past retention")
	}
}

// newEnricher builds the source enricher the configuration describes.
func newEnricher(cfg config.EnrichConfig) (*enrich.Enricher, error) {
	opts := []enrich.Option{
		enrich.WithLookupTimeout(time.Duration(max(cfg.DNSTimeoutSeconds, 1)) * time.Second),
	}
	if cfg.DNSServer != "" {
		opts = append(opts, enrich.WithDNSServer(cfg.DNSServer))
	}
	if !cfg.ReverseDNS {
		opts = append(opts, enrich.WithOffline())
	}
	if cfg.ServiceMap != "" {
		opts = append(opts, enrich.WithServiceMap(cfg.ServiceMap))
	}
	for _, path := range cfg.IPDatabases {
		if path = strings.TrimSpace(path); path != "" {
			opts = append(opts, enrich.WithIPDatabase(path))
		}
	}
	return enrich.New(opts...)
}

// backlogBatch bounds how many addresses stored before enrichment are
// looked up after each fetch.
const backlogBatch = 200

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
func fetchReports(ctx context.Context, source intake.Source, pipeline *ingest.Pipeline, m *metrics.Metrics, timeout time.Duration) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	defer pipeline.EnrichBacklog(ctx, backlogBatch)
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
