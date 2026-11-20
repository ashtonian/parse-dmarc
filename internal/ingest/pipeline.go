// Package ingest turns report mail into stored reports: it parses each
// attachment of a message, stores what parses and tells the message's source
// what became of it.
package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/metrics"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

// Store is where parsed reports go. Each save returns false for a report
// that is already stored.
type Store interface {
	SaveReport(ctx context.Context, feedback *parser.Feedback) (bool, error)
	SaveTLSReport(ctx context.Context, report *parser.TLSReport) (bool, error)
}

// Enricher finds out who sends from an address. *enrich.Enricher is one.
type Enricher interface {
	LookupAll(ctx context.Context, ips []string, concurrency int) map[string]enrich.Source
}

// SourceStore caches what the enricher found, per address.
type SourceStore interface {
	SourcesToLookUp(ctx context.Context, ips []string, staleBefore time.Time) ([]string, error)
	SourcesMissing(ctx context.Context, limit int) ([]string, error)
	SaveSources(ctx context.Context, sources []enrich.Source) error
}

// Pipeline stores the reports of one message at a time. It is an
// intake.Handler through Handle.
type Pipeline struct {
	store   Store
	metrics *metrics.Metrics
	log     *zerolog.Logger

	enricher Enricher
	sources  SourceStore
	refresh  time.Duration
	now      func() time.Time
}

// Option configures a Pipeline.
type Option func(*Pipeline)

// WithEnricher looks up the sending addresses of each new DMARC report,
// caching each address in sources and looking it up again once the cached
// entry is older than refresh.
func WithEnricher(e Enricher, sources SourceStore, refresh time.Duration) Option {
	return func(p *Pipeline) {
		p.enricher, p.sources, p.refresh = e, sources, refresh
	}
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(p *Pipeline) { p.now = now }
}

// New returns a pipeline writing to store. m may be nil.
func New(store Store, m *metrics.Metrics, log *zerolog.Logger, opts ...Option) *Pipeline {
	p := &Pipeline{store: store, metrics: m, log: log, now: time.Now}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// enrichConcurrency bounds the DNS lookups in flight for one report.
const enrichConcurrency = 8

// enrich looks up the addresses that are not cached or whose entry is
// stale. Enrichment is best-effort: a failure is logged and never holds up
// the report.
func (p *Pipeline) enrich(ctx context.Context, ips []string) {
	if p.enricher == nil || len(ips) == 0 {
		return
	}
	todo, err := p.sources.SourcesToLookUp(ctx, ips, p.now().Add(-p.refresh))
	if err != nil {
		p.log.Warn().Err(err).Msg("enrichment: reading the source cache")
		return
	}
	if len(todo) == 0 {
		return
	}
	found := p.enricher.LookupAll(ctx, todo, enrichConcurrency)
	sources := make([]enrich.Source, 0, len(found))
	for _, src := range found {
		sources = append(sources, src)
	}
	if err := p.sources.SaveSources(ctx, sources); err != nil {
		p.log.Warn().Err(err).Msg("enrichment: saving sources")
		return
	}
	p.log.Debug().Int("looked_up", len(sources)).Msg("enriched sending addresses")
}

// EnrichBacklog looks up to limit addresses stored before they could be
// looked up: reports from before enrichment was configured, or whose
// lookup was cut short.
func (p *Pipeline) EnrichBacklog(ctx context.Context, limit int) {
	if p.enricher == nil {
		return
	}
	ips, err := p.sources.SourcesMissing(ctx, limit)
	if err != nil {
		p.log.Warn().Err(err).Msg("enrichment: listing addresses to look up")
		return
	}
	p.enrich(ctx, ips)
}

// Handle parses and stores every report attachment of msg, DMARC or TLS-RPT. A report that
// does not parse is skipped; one that cannot be stored makes the whole
// message a retry, since reading it again may succeed and the reports it
// did store are recognised as duplicates then.
func (p *Pipeline) Handle(ctx context.Context, msg intake.Message) intake.Outcome {
	p.metrics.MessageFetched()

	stored, retry := 0, false
	for _, att := range msg.Attachments {
		p.metrics.AttachmentSeen()

		report, err := parseAttachment(att.Data)
		if err != nil {
			p.log.Warn().Err(err).
				Str("filename", att.Filename).
				Str("message_id", msg.MessageID).
				Str("from", msg.From).
				Msg("failed to parse report")
			p.metrics.ReportParseFailed()
			continue
		}
		p.metrics.ReportParsed()

		saved, err := p.save(ctx, report)
		event := p.log.Info().
			Str("kind", string(report.Kind)).
			Str("message_id", msg.MessageID)
		event = describe(event, report)
		if err != nil {
			p.log.Error().Err(err).
				Str("kind", string(report.Kind)).
				Str("message_id", msg.MessageID).
				Msg("failed to save report")
			p.metrics.ReportStoreFailed()
			retry = true
			continue
		}
		stored++
		if !saved {
			event.Msg("report already stored")
			continue
		}
		p.metrics.ReportStored()
		event.Msg("saved report")
		if report.Kind == parser.KindDMARC {
			p.enrich(ctx, sourceIPs(report.DMARC))
		}
	}

	switch {
	case retry || ctx.Err() != nil:
		return intake.OutcomeRetry
	case stored > 0:
		return intake.OutcomeStored
	default:
		return intake.OutcomeInvalid
	}
}

func (p *Pipeline) save(ctx context.Context, r *parser.Report) (bool, error) {
	switch r.Kind {
	case parser.KindTLSRPT:
		return p.store.SaveTLSReport(ctx, r.TLSRPT)
	default:
		return p.store.SaveReport(ctx, r.DMARC)
	}
}

func sourceIPs(f *parser.Feedback) []string {
	ips := make([]string, 0, len(f.Records))
	for _, r := range f.Records {
		ips = append(ips, r.Row.SourceIP)
	}
	return ips
}

// describe adds what identifies a report to a log entry.
func describe(e *zerolog.Event, r *parser.Report) *zerolog.Event {
	switch r.Kind {
	case parser.KindTLSRPT:
		ok, failed := r.TLSRPT.Sessions()
		return e.Str("report_id", r.TLSRPT.ReportID).
			Str("org", r.TLSRPT.OrganizationName).
			Strs("domains", r.TLSRPT.PolicyDomains()).
			Int64("successful_sessions", ok).
			Int64("failed_sessions", failed)
	default:
		return e.Str("report_id", r.DMARC.ReportMetadata.ReportID).
			Str("org", r.DMARC.ReportMetadata.OrgName).
			Str("domain", r.DMARC.PolicyPublished.Domain).
			Int("messages", r.DMARC.GetTotalMessages())
	}
}

// parseAttachment parses one attachment, DMARC or TLS-RPT. A report that
// crashes the parser is a report that does not parse: one hostile attachment
// must not take the fetch loop down with it.
func parseAttachment(data []byte) (report *parser.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			report, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	return parser.Parse(data)
}
